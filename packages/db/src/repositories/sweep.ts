/**
 * The scheduled expiry sweep.
 *
 * Every runtime table stores an `expires_at`, and every credential is refused on the
 * strength of that column rather than of its absence from the table — so a sweep
 * removes storage, never permission. That is what makes it safe for the one job in
 * Signet that has no tenant: the predicates are properties of the rows themselves,
 * they can only match rows that are already unusable, and nothing but a count is
 * returned.
 *
 * The one exception is deliberately *not* here: access token records are a
 * revocation list, and deleting one early would un-revoke a live token. Their sweep
 * takes an explicit cut-off, and the caller is expected to leave a grace period.
 */

import { deleteExpiredAccessTokens } from "./accessTokens.js";
import { deleteExpiredAdminSessions } from "./adminUsers.js";
import { deleteExpiredAuthorizationCodes } from "./authorizationCodes.js";
import { deleteExpiredAuthorizationSessions } from "./authorizationSessions.js";
import { deleteExpiredConsents } from "./consents.js";
import { deleteExpiredJtis } from "./jtiReplay.js";
import { deleteExpiredLaunchContexts } from "./launchContexts.js";
import { deleteExpiredRefreshTokens } from "./refreshTokens.js";

import type { Executor } from "./executor.js";

/** How many rows each table gave up. */
export interface SweepCounts {
  readonly launchContexts: number;
  readonly authorizationCodes: number;
  readonly authorizationSessions: number;
  readonly accessTokens: number;
  readonly refreshTokens: number;
  readonly consents: number;
  readonly jtiReplay: number;
  /**
   * Console sessions. Not a runtime table, but the same scheduled job: an
   * expired cookie is as dead as an expired code, and one sweep is easier to
   * operate than two.
   */
  readonly adminSessions: number;
}

/** How far back the sweep reaches. */
export interface SweepOptions {
  /**
   * The instant to compare expiries against. Defaults to the database's own
   * transaction time, which is what production should use.
   */
  readonly now?: Date;
  /**
   * Cut-off for access token records, which should lag behind `now`.
   *
   * An introspection request arriving a moment after a token expired should be
   * answered with `active: false` and the token's metadata rather than as an
   * unknown token, and a resource server's clock may be slightly behind Signet's.
   * Defaults to `now`, so a caller that wants the grace period must ask for it.
   */
  readonly accessTokensBefore?: Date;
}

/**
 * Deletes every runtime row that has passed its expiry.
 *
 * Codes are swept before sessions so that the counts mean what they say: sessions
 * cascade to their codes, so sweeping sessions first would silently absorb codes
 * that expired on their own.
 *
 * Not one transaction. Each statement is independent and idempotent, and wrapping
 * a potentially very large multi-table delete in a single transaction on a busy
 * database buys atomicity nobody needs at the cost of a long-held lock footprint.
 */
export async function sweepExpiredRuntimeRows(
  db: Executor,
  options: SweepOptions = {},
): Promise<SweepCounts> {
  const { now } = options;

  const launchContexts = await deleteExpiredLaunchContexts(db, now);
  const authorizationCodes = await deleteExpiredAuthorizationCodes(db, now);
  const authorizationSessions = await deleteExpiredAuthorizationSessions(
    db,
    now,
  );
  const accessTokens = await deleteExpiredAccessTokens(
    db,
    options.accessTokensBefore ?? now,
  );
  const refreshTokens = await deleteExpiredRefreshTokens(db, now);
  const consents = await deleteExpiredConsents(db, now);
  const jtiReplay = await deleteExpiredJtis(db, now);
  const adminSessions = await deleteExpiredAdminSessions(db, now);

  return {
    launchContexts,
    authorizationCodes,
    authorizationSessions,
    accessTokens,
    refreshTokens,
    consents,
    jtiReplay,
    adminSessions,
  };
}
