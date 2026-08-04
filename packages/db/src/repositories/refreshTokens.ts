/**
 * Refresh tokens, rotation, and reuse detection.
 *
 * Signet rotates refresh tokens: every redemption consumes the presented token and
 * issues a successor in the same family. The family is what makes theft
 * detectable. A refresh token is a long-lived bearer credential with no proof of
 * possession, so if an attacker copies one, both parties hold something that
 * looks valid. Rotation guarantees that the second party to present it presents a
 * token that has already been consumed - and that observation is the only signal
 * available that the credential leaked.
 *
 * The response to that signal is to revoke the whole family, not just the token.
 * Revoking only the reused token would leave the successor working, and the
 * successor is as likely to be the attacker's as the victim's; the server cannot
 * tell which party is which and must not guess. Revoking the family logs both out
 * and forces a fresh authorization, which the legitimate user can complete and the
 * attacker cannot.
 *
 * Redemption is a conditional `UPDATE ... RETURNING` for the same reason
 * authorization codes are: two concurrent redemptions of one token must produce one
 * successor, and only the database can decide that.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9700 (OAuth 2.0 Security Best
 *   Current Practice, refresh token protection)
 *
 * Author: John Grimes
 */

import { and, desc, eq, gt, isNull, lte } from "drizzle-orm";

import {
  classifyRefreshTokenRefusal,
  shouldRevokeFamily,
} from "./predicates.js";
import { firstRow, requireRow } from "./rows.js";
import { databaseNow, TenantScopeViolationError } from "./scope.js";
import { nowValue } from "./time.js";
import { refreshTokens } from "../schema/runtime.js";

import type { Executor } from "./executor.js";
import type { RefreshTokenRefusal } from "./predicates.js";
import type { ClientScope, EndpointScope } from "./scope.js";
import type { NewRefreshToken, RefreshToken } from "../schema/runtime.js";
import type { SQL } from "drizzle-orm";

/**
 * The caller-supplied half of a refresh token.
 *
 * `familyId` is optional: omitting it starts a new family, which is what an
 * authorization-code grant does. {@link rotateRefreshToken} supplies the
 * predecessor's family instead, so a rotation can never accidentally begin a new
 * one - which would make the old token's reuse undetectable.
 */
export type RefreshTokenInput = Omit<
  NewRefreshToken,
  | "id"
  | "endpointId"
  | "clientId"
  | "issuedAt"
  | "revokedAt"
  | "replacedById"
  | "familyId"
> & { readonly familyId?: string };

/**
 * Issues a refresh token to the scoped client, starting a new family.
 *
 * Called after an authorization-code grant. Rotation goes through
 * {@link rotateRefreshToken}.
 */
export async function issueRefreshToken(
  db: Executor,
  scope: ClientScope,
  input: RefreshTokenInput,
): Promise<RefreshToken> {
  const rows = await db
    .insert(refreshTokens)
    .values({
      ...input,
      familyId: input.familyId ?? crypto.randomUUID(),
      endpointId: scope.endpointId,
      clientId: scope.clientRowId,
    })
    .returning();
  return requireRow(rows, "insert into refresh_tokens");
}

/** The outcome of presenting a refresh token. */
export type RefreshTokenRedemption =
  | { readonly ok: true; readonly token: RefreshToken }
  | {
      readonly ok: false;
      readonly reason: RefreshTokenRefusal;
      /**
       * How many tokens the reuse response revoked. Non-zero only when `reason`
       * is `reused`, and worth an audit event of its own when it is.
       */
      readonly familyRevoked: number;
    };

/**
 * Claims a presented refresh token, or detects its reuse.
 *
 * The claim marks the token revoked before any successor exists. That ordering is
 * what makes reuse detectable at all: the token is spent the instant it is
 * accepted, so a second presentation cannot claim it, whatever happens next. If
 * issuing the successor then fails, the family survives with a revoked leaf and
 * no successor - the user must reauthorise, which is inconvenient and correct.
 * See `classifyRefreshTokenRefusal` for why that case is *not* treated as theft.
 *
 * On reuse, the whole family is revoked before returning.
 */
export async function redeemRefreshToken(
  db: Executor,
  scope: EndpointScope,
  tokenHash: string,
  now?: Date,
): Promise<RefreshTokenRedemption> {
  return await db.transaction(async (tx) => {
    const claimed = await tx
      .update(refreshTokens)
      .set({ revokedAt: nowValue(now) })
      .where(
        and(
          eq(refreshTokens.tokenHash, tokenHash),
          eq(refreshTokens.endpointId, scope.endpointId),
          isNull(refreshTokens.revokedAt),
          isNull(refreshTokens.replacedById),
          // Strictly greater than: a token expiring exactly now is expired,
          // matching the pure predicates.
          gt(refreshTokens.expiresAt, nowValue(now)),
        ),
      )
      .returning();

    const token = firstRow(claimed);
    if (token !== undefined) {
      return { ok: true, token };
    }

    const existing = await findRefreshToken(tx, scope, tokenHash);
    const at = now ?? (await databaseNow(tx));
    const reason = classifyRefreshTokenRefusal(existing, at);

    const familyRevoked =
      shouldRevokeFamily(reason) && existing !== undefined
        ? await revokeRefreshTokenFamily(tx, scope, existing.familyId, now)
        : 0;

    return { ok: false, reason, familyRevoked };
  });
}

/**
 * Issues the successor to a claimed token, in the same family.
 *
 * The predecessor must be a row returned by {@link redeemRefreshToken}: it carries
 * the family the successor joins and the subject it belongs to, and it proves the
 * token was claimed rather than merely read. Its endpoint and client are checked
 * against the scope, because rotating a token into a different client's family
 * would break the very property the family exists to provide.
 *
 * The successor's scopes may narrow but must never widen. That is a policy
 * judgement, made in `@signet/core` before this is called - the repository stores
 * what it is given.
 */
export async function rotateRefreshToken(
  db: Executor,
  scope: ClientScope,
  redeemed: RefreshToken,
  replacement: Omit<RefreshTokenInput, "familyId" | "subject"> & {
    readonly subject?: string;
  },
): Promise<RefreshToken> {
  if (
    redeemed.endpointId !== scope.endpointId ||
    redeemed.clientId !== scope.clientRowId
  ) {
    throw new TenantScopeViolationError(
      `refresh token ${redeemed.id} does not belong to client ${scope.clientRowId} on endpoint ${scope.endpointId}`,
    );
  }

  return await db.transaction(async (tx) => {
    const successor = await issueRefreshToken(tx, scope, {
      ...replacement,
      subject: replacement.subject ?? redeemed.subject,
      familyId: redeemed.familyId,
    });

    const linked = await tx
      .update(refreshTokens)
      .set({ replacedById: successor.id })
      .where(
        and(
          eq(refreshTokens.id, redeemed.id),
          isNull(refreshTokens.replacedById),
        ),
      )
      .returning({ id: refreshTokens.id });

    // The predecessor was claimed by this transaction's caller, so nothing else
    // can have linked a successor to it. If that is untrue the family's integrity
    // is already gone, and continuing would hide it.
    requireRow(linked, "link refresh_tokens successor");

    return successor;
  });
}

/** The outcome of a full rotation. */
export type RefreshTokenRotation =
  | {
      readonly ok: true;
      readonly redeemed: RefreshToken;
      readonly replacement: RefreshToken;
    }
  | {
      readonly ok: false;
      readonly reason: RefreshTokenRefusal;
      readonly familyRevoked: number;
    };

/**
 * Claims a presented token and issues its successor, in one transaction.
 *
 * This is what the `refresh_token` grant should call. Doing both halves in one
 * transaction means a failure between them rolls the claim back, so the client can
 * retry with the token it still holds instead of being logged out by a transient
 * database error.
 */
export async function redeemAndRotateRefreshToken(
  db: Executor,
  scope: ClientScope,
  tokenHash: string,
  replacement: Omit<RefreshTokenInput, "familyId" | "subject"> & {
    readonly subject?: string;
  },
  now?: Date,
): Promise<RefreshTokenRotation> {
  return await db.transaction(async (tx) => {
    const redemption = await redeemRefreshToken(tx, scope, tokenHash, now);
    if (!redemption.ok) {
      return redemption;
    }

    const successor = await rotateRefreshToken(
      tx,
      scope,
      redemption.token,
      replacement,
    );

    return { ok: true, redeemed: redemption.token, replacement: successor };
  });
}

/** Reads a refresh token by digest within the scoped endpoint. */
export async function findRefreshToken(
  db: Executor,
  scope: EndpointScope,
  tokenHash: string,
): Promise<RefreshToken | undefined> {
  const [row] = await db
    .select()
    .from(refreshTokens)
    .where(
      and(
        eq(refreshTokens.tokenHash, tokenHash),
        eq(refreshTokens.endpointId, scope.endpointId),
      ),
    )
    .limit(1);
  return row;
}

/**
 * Revokes every live token in one rotation family.
 *
 * The endpoint predicate is applied as well as the family identifier: a family
 * identifier is a UUID a caller could in principle have obtained anywhere, and
 * this is a destructive operation.
 *
 * Access tokens are not touched. They are separately revocable and typically
 * expire in minutes, whereas a refresh family lives for weeks; the grant handler
 * decides whether the incident also warrants revoking the short-lived tokens.
 *
 * @returns How many tokens were revoked.
 */
export async function revokeRefreshTokenFamily(
  db: Executor,
  scope: EndpointScope,
  familyId: string,
  now?: Date,
): Promise<number> {
  const rows = await db
    .update(refreshTokens)
    .set({ revokedAt: nowValue(now) })
    .where(
      and(
        eq(refreshTokens.familyId, familyId),
        eq(refreshTokens.endpointId, scope.endpointId),
        isNull(refreshTokens.revokedAt),
      ),
    )
    .returning({ id: refreshTokens.id });
  return rows.length;
}

/**
 * Revokes the live refresh tokens a predicate selects.
 *
 * The three revocations below differ only in what they select. The statement is the part
 * that must not be copied: a version that forgot `isNull(revokedAt)` would restamp an
 * already-revoked row and report it as newly revoked, which is a misleading number in
 * an audit event about a compromise.
 */
async function revokeMatchingRefreshTokens(
  db: Executor,
  predicate: SQL | undefined,
  now?: Date,
): Promise<number> {
  const rows = await db
    .update(refreshTokens)
    .set({ revokedAt: nowValue(now) })
    .where(and(predicate, isNull(refreshTokens.revokedAt)))
    .returning({ id: refreshTokens.id });
  return rows.length;
}

/**
 * Revokes every live refresh token issued to the scoped client.
 *
 * @returns How many tokens were revoked.
 */
export async function revokeRefreshTokensForClient(
  db: Executor,
  scope: ClientScope,
  now?: Date,
): Promise<number> {
  return await revokeMatchingRefreshTokens(
    db,
    and(
      eq(refreshTokens.clientId, scope.clientRowId),
      eq(refreshTokens.endpointId, scope.endpointId),
    ),
    now,
  );
}

/**
 * Revokes every live refresh token for one subject on the scoped endpoint.
 *
 * This is "sign this person out of everything".
 *
 * @returns How many tokens were revoked.
 */
export async function revokeRefreshTokensForSubject(
  db: Executor,
  scope: EndpointScope,
  subject: string,
  now?: Date,
): Promise<number> {
  return await revokeMatchingRefreshTokens(
    db,
    and(
      eq(refreshTokens.subject, subject),
      eq(refreshTokens.endpointId, scope.endpointId),
    ),
    now,
  );
}

/**
 * Revokes one subject's live refresh tokens for one client.
 *
 * The management page's "disconnect this app": revoking every token the person holds
 * would disconnect apps they did not ask to disconnect.
 *
 * @returns How many tokens were revoked.
 */
export async function revokeRefreshTokensForSubjectAndClient(
  db: Executor,
  scope: ClientScope,
  subject: string,
  now?: Date,
): Promise<number> {
  return await revokeMatchingRefreshTokens(
    db,
    and(
      eq(refreshTokens.subject, subject),
      eq(refreshTokens.endpointId, scope.endpointId),
      eq(refreshTokens.clientId, scope.clientRowId),
    ),
    now,
  );
}

/** Lists a subject's refresh tokens on the scoped endpoint, newest first. */
export async function listRefreshTokensForSubject(
  db: Executor,
  scope: EndpointScope,
  subject: string,
): Promise<readonly RefreshToken[]> {
  return await db
    .select()
    .from(refreshTokens)
    .where(
      and(
        eq(refreshTokens.subject, subject),
        eq(refreshTokens.endpointId, scope.endpointId),
      ),
    )
    .orderBy(desc(refreshTokens.issuedAt));
}

/**
 * Deletes refresh tokens past their expiry.
 *
 * An expired token cannot be redeemed by the conditional claim, so keeping it
 * protects nothing: a reuse attempt on an expired token is already refused. What
 * does matter is that a *live* family member is never deleted, or reuse detection
 * would lose its history - hence the predicate is on the row's own expiry and
 * nothing else.
 *
 * @returns How many rows were deleted.
 */
export async function deleteExpiredRefreshTokens(
  db: Executor,
  before?: Date,
): Promise<number> {
  const rows = await db
    .delete(refreshTokens)
    .where(lte(refreshTokens.expiresAt, nowValue(before)))
    .returning({ id: refreshTokens.id });
  return rows.length;
}
