/**
 * The scheduled expiry sweep - the one job in Signet that acts across tenants.
 *
 * Every runtime table stores an `expires_at`, and every credential is refused on the
 * strength of that column rather than of its absence from the table - so a sweep
 * removes storage, never permission. That is what makes a job with no tenant
 * acceptable: the predicates are properties of the rows themselves, they can only
 * match rows that are already unusable, and nothing but a count is returned.
 *
 * The one exception is deliberately *not* here: access token records are a
 * revocation list, and deleting one early would un-revoke a live token. Their sweep
 * takes an explicit cut-off, and the caller is expected to leave a grace period.
 *
 * ## Which identity this needs, and why it cannot be the server's
 *
 * The owning identity. Acting across tenants is exactly what the serving role must
 * not be able to do, so this is not a capability the running server has: reached
 * with the serving role, every statement below matches nothing, because the
 * policies hide every row from a connection that has declared no tenant. That is
 * asserted in `./repositories.integration.test.ts`, and it is the reason the
 * function can safely remain callable at all - there is no partial outcome, and its
 * existence grants the server nothing.
 *
 * ## Who calls it
 *
 * `apps/server/src/sweep.ts`, as the `sweep` command, which the Helm chart runs on
 * a nightly CronJob. That command observes the role it was given before deleting
 * anything and refuses one the policies bind, because the alternative - every
 * count coming back zero - is indistinguishable from a database with nothing to
 * reclaim. There is still no route: this is a maintenance job, not a request.
 *
 * Author: John Grimes
 */

import { deleteExpiredAccessTokens } from "./accessTokens.js";
import { deleteExpiredAdminPasskeyChallenges } from "./adminPasskeys.js";
import { deleteExpiredAdminSessions } from "./adminUsers.js";
import { deleteExpiredAuthorizationCodes } from "./authorizationCodes.js";
import { deleteExpiredAuthorizationSessions } from "./authorizationSessions.js";
import { deleteExpiredConsents } from "./consents.js";
import { deleteExpiredEndUserSessions } from "./endUserSessions.js";
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
  /** End users' management-page sessions, for the same reason. */
  readonly endUserSessions: number;
  /**
   * Passkey ceremony challenges that were issued and never completed.
   *
   * A browser prompt somebody dismissed leaves one behind, so these accumulate in
   * ordinary use rather than only when something goes wrong.
   */
  readonly passkeyChallenges: number;
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
 *
 * @param db - A connection with the owning identity; see the module header. Given
 *   the serving role every count comes back zero.
 * @param options - How far back to reach.
 * @returns How many rows each table gave up.
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
  const endUserSessions = await deleteExpiredEndUserSessions(db, now);
  const passkeyChallenges = await deleteExpiredAdminPasskeyChallenges(db, now);

  return {
    launchContexts,
    authorizationCodes,
    authorizationSessions,
    accessTokens,
    refreshTokens,
    consents,
    jtiReplay,
    adminSessions,
    endUserSessions,
    passkeyChallenges,
  };
}
