/**
 * Pure decisions about the state of a persisted row.
 *
 * Everything here is a total function of its arguments with no database access,
 * because these are the judgements that decide whether a credential is honoured:
 * whether a token is still live, whether a refresh token has been reused, how
 * many versions a policy has. Keeping them out of the query layer means they can
 * be tested exhaustively - including the boundaries, which is where an
 * authorization server gets these wrong.
 *
 * The inputs are deliberately narrow structural types rather than whole rows.
 * A test does not have to fabricate twelve irrelevant columns to assert one
 * boundary, and the same predicate serves any row that carries the same shape.
 *
 * Every comparison treats an expiry falling exactly on `now` as expired. That
 * matches the SQL predicates used for the atomic claims (`expires_at > now()`),
 * and erring the other way would honour a credential one tick past its lifetime.
 *
 * Author: John Grimes
 */

import type { ClientType } from "@signet/core";

/** A row with a lifetime that may be unbounded. */
export interface Expirable {
  readonly expiresAt: Date | null;
}

/** A row that can be revoked without being deleted. */
export interface Revocable {
  readonly revokedAt: Date | null;
}

/** A single-use row that records its redemption. */
export interface Consumable {
  readonly consumedAt: Date | null;
  readonly expiresAt: Date;
}

/** Whether a lifetime has run out. A null expiry never does. */
export function isExpired(expiresAt: Date | null, now: Date): boolean {
  return expiresAt !== null && expiresAt.getTime() <= now.getTime();
}

/** Whether a revocable row has been revoked. */
export function isRevoked(row: Revocable): boolean {
  return row.revokedAt !== null;
}

/** Whether a revocable, expiring row is still usable. */
export function isLive(row: Revocable & Expirable, now: Date): boolean {
  return !isRevoked(row) && !isExpired(row.expiresAt, now);
}

/** The state introspection reports for an access token. */
export type TokenState = "active" | "revoked" | "expired";

/**
 * Classifies an access token.
 *
 * Revocation is reported ahead of expiry because it is the more specific fact:
 * both answer `active: false` to an introspection request, but only one of them
 * is worth an audit event.
 */
export function accessTokenState(
  token: Revocable & { readonly expiresAt: Date },
  now: Date,
): TokenState {
  if (isRevoked(token)) {
    return "revoked";
  }
  return isExpired(token.expiresAt, now) ? "expired" : "active";
}

/** Why a single-use row could not be redeemed. */
export type ConsumptionRefusal = "not-found" | "already-consumed" | "expired";

/**
 * Explains why an atomic claim on a single-use row failed.
 *
 * This runs only after the conditional `UPDATE` has already declined to claim
 * the row, so it decides nothing - it exists so that the caller can audit a
 * replayed authorization code differently from one that merely timed out.
 * Consumption is reported ahead of expiry: a code that was redeemed and then sat
 * around until it expired was still, first and foremost, replayed.
 */
export function classifyConsumptionRefusal(
  row: Consumable | undefined,
  now: Date,
): ConsumptionRefusal {
  if (row === undefined) {
    return "not-found";
  }
  if (row.consumedAt !== null) {
    return "already-consumed";
  }
  return isExpired(row.expiresAt, now) ? "expired" : "not-found";
}

/** A launch handle as redemption sees it. */
export interface RedeemableHandle extends Consumable {
  /** The client the handle was minted for, or null when it is unbound. */
  readonly clientId: string | null;
}

/** Why a launch handle could not be redeemed. */
export type LaunchHandleRefusal = ConsumptionRefusal | "client-mismatch";

/**
 * Explains why an atomic claim on a launch handle failed.
 *
 * A mismatched client is reported ahead of consumption and expiry. An EHR that
 * mints a handle for one app and sees it presented by another has been handed
 * evidence of a leaked handle, and that is a different event from an app
 * retrying its own launch - so it must not be flattened into
 * `already-consumed`.
 *
 * Note that a handle stays unredeemable by the wrong client even after it has
 * been consumed: the mismatch is the more serious fact, and reporting it first
 * costs nothing since neither outcome grants anything.
 */
export function classifyLaunchHandleRefusal(
  row: RedeemableHandle | undefined,
  clientRowId: string,
  now: Date,
): LaunchHandleRefusal {
  if (
    row !== undefined &&
    row.clientId !== null &&
    row.clientId !== clientRowId
  ) {
    return "client-mismatch";
  }
  return classifyConsumptionRefusal(row, now);
}

/** A refresh token as reuse detection sees it. */
export interface RotatableToken extends Revocable {
  readonly expiresAt: Date;
  /** The successor issued when this token was rotated, if it was. */
  readonly replacedById: string | null;
}

/** Why a refresh token could not be redeemed. */
export type RefreshTokenRefusal =
  "not-found" | "reused" | "revoked" | "expired";

/**
 * Explains why an atomic claim on a refresh token failed.
 *
 * The ordering here *is* the reuse detection. A token that has a successor has
 * already been rotated, so presenting it again means two parties hold it and one
 * of them should not - that verdict is returned ahead of both revocation and
 * expiry, because a rotated token is necessarily also revoked, and because a
 * stolen token presented after its own expiry is still evidence of theft.
 *
 * A token that is revoked with no successor is reported as merely revoked. That
 * covers an end user revoking access from the management page, and it covers a
 * redemption that claimed the token and then failed before issuing the
 * replacement. Treating the latter as theft would revoke a whole token family
 * every time the server hit a transient error mid-rotation, which would turn an
 * outage into a mass logout.
 */
export function classifyRefreshTokenRefusal(
  token: RotatableToken | undefined,
  now: Date,
): RefreshTokenRefusal {
  if (token === undefined) {
    return "not-found";
  }
  if (token.replacedById !== null) {
    return "reused";
  }
  if (isRevoked(token)) {
    return "revoked";
  }
  return isExpired(token.expiresAt, now) ? "expired" : "not-found";
}

/**
 * Whether a refusal means the whole rotation family must be revoked.
 *
 * Only reuse does. This is a one-line function so that the rule has one place to
 * live and one place to be tested, rather than being an `if` inside a query.
 */
export function shouldRevokeFamily(refusal: RefreshTokenRefusal): boolean {
  return refusal === "reused";
}

/** The version number to allocate next for an endpoint's policy. */
export function nextPolicyVersion(highestExisting: number | null): number {
  return highestExisting === null ? 1 : highestExisting + 1;
}

/**
 * Whether an end user may be picked from the persona list.
 *
 * Personas have no password by design, so offering one on a production endpoint
 * would be an unauthenticated login. Both halves of the condition are checked
 * here rather than being spread between a query filter and a handler, so that
 * neither can be relaxed without the other.
 */
export function isPersonaSelectable(
  endpoint: { readonly isProduction: boolean },
  user: { readonly isPersona: boolean; readonly disabledAt: Date | null },
): boolean {
  return !endpoint.isProduction && user.isPersona && user.disabledAt === null;
}

/** Whether an end user may authenticate at all. */
export function isEndUserEnabled(user: {
  readonly disabledAt: Date | null;
}): boolean {
  return user.disabledAt === null;
}

/** Whether a client may be issued a token. */
export function isClientUsable(client: { readonly status: string }): boolean {
  return client.status === "active";
}

/** The three client-type admission flags an endpoint carries. */
export interface ClientTypeAdmission {
  readonly allowsPublicClients: boolean;
  readonly allowsConfidentialSymmetricClients: boolean;
  readonly allowsConfidentialAsymmetricClients: boolean;
}

/**
 * Whether an endpoint admits a client of this type at all.
 *
 * Asked wherever a client is created - the console, the developer portal's
 * approval, and vouched registration - because an endpoint that refuses a type
 * should refuse to register one rather than registering it and then refusing
 * every authorization it attempts. The second produces a client that appears
 * configured and never works.
 *
 * @param endpoint - The endpoint's admission flags.
 * @param clientType - The type being registered.
 * @returns Whether the registration may proceed.
 * @example
 * ```ts
 * if (!endpointAllowsClientType(endpoint, metadata.clientType)) {
 *   return refuse("invalid_client_metadata", "…");
 * }
 * ```
 */
export function endpointAllowsClientType(
  endpoint: ClientTypeAdmission,
  clientType: ClientType,
): boolean {
  switch (clientType) {
    case "public": {
      return endpoint.allowsPublicClients;
    }
    case "confidential-symmetric": {
      return endpoint.allowsConfidentialSymmetricClients;
    }
    case "confidential-asymmetric": {
      return endpoint.allowsConfidentialAsymmetricClients;
    }
  }
}
