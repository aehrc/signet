/**
 * Single-use authorization codes.
 *
 * {@link consumeAuthorizationCode} is the most safety-critical statement in this
 * package. An authorization code is a bearer credential that converts into an
 * access token, and a code that can be redeemed twice is two tokens from one
 * consent - the classic replay against which RFC 6749 section 10.5 requires
 * single use.
 *
 * It is therefore a conditional `UPDATE ... WHERE consumed_at IS NULL RETURNING`,
 * not a read followed by a write. Two concurrent redemptions both reach the row,
 * but Postgres serialises them on the row lock: the first sets `consumed_at` and
 * the second re-evaluates its predicate against the committed row, matches
 * nothing, and returns no rows. Only the caller holding a returned row may
 * proceed, and there is no instant at which both do.
 *
 * A read-then-write would fail in exactly the way that is hardest to notice -
 * correct in every test, wrong under load, and wrong in the direction of issuing
 * an extra token.
 *
 * Author: John Grimes
 */

import { and, eq, exists, gt, isNull, lte, sql } from "drizzle-orm";

import { classifyConsumptionRefusal } from "./predicates.js";
import { firstRow, requireRow } from "./rows.js";
import {
  executorFor,
  databaseNow,
  TenantScopeViolationError,
} from "./scope.js";
import { nowValue } from "./time.js";
import {
  authorizationCodes,
  authorizationSessions,
} from "../schema/runtime.js";

import type { Executor } from "./executor.js";
import type { ConsumptionRefusal } from "./predicates.js";
import type { BoundEndpointScope } from "./scope.js";
import type {
  AuthorizationCode,
  AuthorizationSession,
} from "../schema/runtime.js";

/** What is needed to issue an authorization code. */
export interface AuthorizationCodeInput {
  /** SHA-256 of the code. The code itself is never stored. */
  readonly codeHash: string;
  readonly expiresAt: Date;
}

/**
 * Issues a code against a session.
 *
 * The session is passed as a row rather than an identifier: a row can only have
 * come from a scoped read, so a code cannot be minted against a session belonging
 * to another endpoint. The mismatch check is an assertion about the caller's own
 * consistency, not a permission decision, so it throws.
 */
export async function createAuthorizationCode(
  scope: BoundEndpointScope,
  session: AuthorizationSession,
  input: AuthorizationCodeInput,
): Promise<AuthorizationCode> {
  if (session.endpointId !== scope.endpointId) {
    throw new TenantScopeViolationError(
      `session ${session.id} belongs to endpoint ${session.endpointId}, not ${scope.endpointId}`,
    );
  }

  const rows = await executorFor(scope)
    .insert(authorizationCodes)
    .values({
      codeHash: input.codeHash,
      sessionId: session.id,
      expiresAt: input.expiresAt,
    })
    .returning();

  return requireRow(rows, "insert into authorization_codes");
}

/** The outcome of redeeming an authorization code. */
export type AuthorizationCodeRedemption =
  | {
      readonly ok: true;
      readonly code: AuthorizationCode;
      readonly session: AuthorizationSession;
    }
  | { readonly ok: false; readonly reason: ConsumptionRefusal };

/**
 * Correlated `EXISTS` restricting a code to the scoped endpoint.
 *
 * `authorization_codes` has no `endpoint_id` of its own - it hangs off the
 * session - so the tenant predicate has to be a subquery. Putting it inside the
 * conditional `UPDATE` rather than checking it afterwards keeps the claim atomic:
 * a code belonging to another endpoint is never consumed at all, not consumed and
 * then rejected.
 */
function belongsToEndpoint(scope: BoundEndpointScope) {
  return exists(
    executorFor(scope)
      .select({ one: sql`1` })
      .from(authorizationSessions)
      .where(
        and(
          eq(authorizationSessions.id, authorizationCodes.sessionId),
          eq(authorizationSessions.endpointId, scope.endpointId),
        ),
      ),
  );
}

/**
 * Redeems an authorization code, exactly once.
 *
 * @returns The claimed code and the session it authorises, or why it could not be
 *   claimed. `already-consumed` is the replay case, and the token endpoint should
 *   treat it as an attack on the client - the spec permits revoking the tokens
 *   previously issued from that code.
 */
export async function consumeAuthorizationCode(
  scope: BoundEndpointScope,
  codeHash: string,
  now?: Date,
): Promise<AuthorizationCodeRedemption> {
  const claimed = await executorFor(scope)
    .update(authorizationCodes)
    .set({ consumedAt: nowValue(now) })
    .where(
      and(
        eq(authorizationCodes.codeHash, codeHash),
        isNull(authorizationCodes.consumedAt),
        gt(authorizationCodes.expiresAt, nowValue(now)),
        belongsToEndpoint(scope),
      ),
    )
    .returning();

  const code = firstRow(claimed);
  if (code !== undefined) {
    const sessions = await executorFor(scope)
      .select()
      .from(authorizationSessions)
      .where(eq(authorizationSessions.id, code.sessionId))
      .limit(1);

    // The foreign key guarantees the session exists, and the claim above
    // guaranteed it belongs to this endpoint.
    return {
      ok: true,
      code,
      session: requireRow(sessions, "select authorization_sessions for code"),
    };
  }

  const existing = await findAuthorizationCode(scope, codeHash);
  const at = now ?? (await databaseNow(executorFor(scope)));
  return { ok: false, reason: classifyConsumptionRefusal(existing, at) };
}

/**
 * Reads a code by digest, without redeeming it.
 *
 * Restricted to the scoped endpoint through the same `EXISTS` as the claim, so a
 * code minted elsewhere reads as absent.
 */
export async function findAuthorizationCode(
  scope: BoundEndpointScope,
  codeHash: string,
): Promise<AuthorizationCode | undefined> {
  const rows = await executorFor(scope)
    .select()
    .from(authorizationCodes)
    .where(
      and(eq(authorizationCodes.codeHash, codeHash), belongsToEndpoint(scope)),
    )
    .limit(1);
  return firstRow(rows);
}

/**
 * Deletes codes past their expiry.
 *
 * Consumed codes are deleted too, once expired. Retaining them would only be
 * useful for detecting a replay after the fact, and the audit event written at
 * redemption already records that - an audit log is the right place for history,
 * and a runtime table is not.
 *
 * @returns How many rows were deleted.
 */
export async function deleteExpiredAuthorizationCodes(
  db: Executor,
  now?: Date,
): Promise<number> {
  const rows = await db
    .delete(authorizationCodes)
    .where(lte(authorizationCodes.expiresAt, nowValue(now)))
    .returning({ id: authorizationCodes.id });
  return rows.length;
}
