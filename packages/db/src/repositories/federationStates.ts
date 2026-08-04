/**
 * Federation round trips: written on the way out, claimed on the way back.
 *
 * {@link consumeFederationState} is the safety-critical statement here, for the
 * same reason `consumeAuthorizationCode` is in its own module: a callback that can
 * be replayed is a sign-in that can be replayed. It is a conditional
 * `UPDATE ... WHERE consumed_at IS NULL RETURNING` rather than a read followed by
 * a write, so two concurrent callbacks serialise on the row lock and exactly one
 * of them comes away with a row.
 *
 * Everything is endpoint-scoped, including the lookup by state digest. A state
 * minted on one endpoint therefore reads as absent on another, which matters
 * because the callback URL is per-endpoint and a state presented to the wrong one
 * would otherwise complete a sign-in against a set of accounts it was never
 * authorised for.
 *
 * Author: John Grimes
 */

import { and, eq, gt, isNull } from "drizzle-orm";

import { firstRow, requireRow } from "./rows.js";
import { TenantScopeViolationError } from "./scope.js";
import { nowValue } from "./time.js";
import { authorizationSessions, federationStates } from "../schema/runtime.js";

import type { Executor } from "./executor.js";
import type { EndpointScope } from "./scope.js";
import type {
  AuthorizationSession,
  FederationState,
} from "../schema/runtime.js";

/** What is needed to start a round trip. */
export interface FederationStateInput {
  /** SHA-256 of the `state` sent upstream. */
  readonly stateHash: string;
  /** Compared against the ID token's `nonce` on the way back. */
  readonly nonce: string;
  /** The PKCE verifier whose challenge went upstream. */
  readonly codeVerifier: string;
  readonly expiresAt: Date;
}

/**
 * Records a round trip against an authorization session.
 *
 * The session is passed as a row rather than an identifier, so a state cannot be
 * minted against a session belonging to another endpoint. The mismatch is an
 * assertion about the caller's own consistency, not a permission decision, so it
 * throws rather than returning a refusal.
 *
 * @param db - The connection to use.
 * @param scope - The endpoint the session belongs to.
 * @param session - The authorization the sign-in is part of.
 * @param input - The state digest, nonce, verifier and expiry.
 */
export async function createFederationState(
  db: Executor,
  scope: EndpointScope,
  session: AuthorizationSession,
  input: FederationStateInput,
): Promise<FederationState> {
  if (session.endpointId !== scope.endpointId) {
    throw new TenantScopeViolationError(
      `session ${session.id} belongs to endpoint ${session.endpointId}, not ${scope.endpointId}`,
    );
  }

  const rows = await db
    .insert(federationStates)
    .values({
      endpointId: scope.endpointId,
      sessionId: session.id,
      stateHash: input.stateHash,
      nonce: input.nonce,
      codeVerifier: input.codeVerifier,
      expiresAt: input.expiresAt,
    })
    .returning();

  return requireRow(rows, "insert into federation_states");
}

/** A claimed round trip and the authorization it belongs to. */
export interface ClaimedFederationState {
  readonly state: FederationState;
  readonly session: AuthorizationSession;
}

/**
 * Claims a round trip by its state digest, exactly once.
 *
 * Expiry is part of the claim predicate rather than a check afterwards, so a state
 * that timed out is never consumed at all.
 *
 * @param db - The connection to use.
 * @param scope - The endpoint the callback arrived at.
 * @param stateHash - SHA-256 of the `state` the browser presented.
 * @param now - The current time, injected in tests.
 * @returns The claimed row and its session, or undefined for a state that is
 *   unknown, expired, already used, or another endpoint's. The cases are
 *   deliberately not distinguished: the caller answers all of them identically,
 *   and a callback handler that reports which one it hit is an oracle.
 */
export async function consumeFederationState(
  db: Executor,
  scope: EndpointScope,
  stateHash: string,
  now?: Date,
): Promise<ClaimedFederationState | undefined> {
  return await db.transaction(async (tx) => {
    const claimed = await tx
      .update(federationStates)
      .set({ consumedAt: nowValue(now) })
      .where(
        and(
          eq(federationStates.stateHash, stateHash),
          eq(federationStates.endpointId, scope.endpointId),
          isNull(federationStates.consumedAt),
          gt(federationStates.expiresAt, nowValue(now)),
        ),
      )
      .returning();

    const state = firstRow(claimed);
    if (state === undefined) {
      return;
    }

    // The session may have expired while the person was upstream. Filtered here
    // rather than trusted, because the foreign key guarantees the row exists but
    // says nothing about whether it is still live.
    const sessions = await tx
      .select()
      .from(authorizationSessions)
      .where(
        and(
          eq(authorizationSessions.id, state.sessionId),
          gt(authorizationSessions.expiresAt, nowValue(now)),
        ),
      )
      .limit(1);

    const session = firstRow(sessions);
    return session === undefined ? undefined : { state, session };
  });
}

/**
 * Reads a round trip by digest without claiming it.
 *
 * Exists for the tests and for the audit trail, not for the callback path - a
 * handler that reads first and updates second is the race this module is written
 * to avoid.
 *
 * @param db - The connection to use.
 * @param scope - The endpoint the state belongs to.
 * @param stateHash - SHA-256 of the `state`.
 */
export async function findFederationState(
  db: Executor,
  scope: EndpointScope,
  stateHash: string,
): Promise<FederationState | undefined> {
  const rows = await db
    .select()
    .from(federationStates)
    .where(
      and(
        eq(federationStates.stateHash, stateHash),
        eq(federationStates.endpointId, scope.endpointId),
      ),
    )
    .limit(1);
  return firstRow(rows);
}
