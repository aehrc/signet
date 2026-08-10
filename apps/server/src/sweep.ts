/**
 * The `sweep` command.
 *
 * Run as `node dist/index.js sweep`, which is what the Helm chart's CronJob
 * invokes. It deletes every runtime row that has passed its expiry - authorization
 * codes, sessions, consents, `jti` records, console and end-user sessions, and
 * passkey ceremony challenges - across every tenant.
 *
 * Nothing depends on it running: every row it removes is refused on the strength
 * of its own `expires_at` rather than of its presence in the table, so the sweep
 * reclaims storage and never grants or revokes anything. What makes it worth
 * scheduling is `admin_passkey_challenges`, which grows in ordinary use rather
 * than only when something goes wrong: a challenge row is written every time a
 * sign-in or registration ceremony starts, and deleted only when one completes, so
 * every browser prompt somebody dismisses leaves one behind.
 *
 * ## Which identity this needs, and why the command checks
 *
 * The owning identity, for the reason `migrate` needs it: acting across tenants is
 * exactly what the serving role must not be able to do. Given the serving role the
 * policies hide every tenant-owned row, so the sweep deletes nothing and every
 * count comes back zero - which is indistinguishable from a database with nothing
 * to reclaim. A nightly CronJob configured that way would report success for
 * months while the tables it was meant to be trimming grew.
 *
 * So the role is observed before anything is deleted, and a connection the policies
 * bind is refused rather than swept with. That is the same observation the server
 * makes at startup, read the other way round - see `./enforcement.ts`, which
 * refuses the identity this command requires.
 *
 * Author: John Grimes
 */

import {
  classifySweepIdentity,
  createDatabase,
  observeEnforcement,
  sweepExpiredRuntimeRows,
} from "@signet/db";

import { ConfigError } from "./config.js";

import type { SweepConfiguration } from "./config.js";
import type { SweepCounts } from "@signet/db";

/**
 * The run's result, as the line an operator reads out of the job's log.
 *
 * `deleted` is summed over the counts rather than added up field by field, so a
 * runtime table that joins the sweep later cannot be silently left out of the
 * number somebody is watching.
 *
 * @param counts - What the sweep reported.
 * @returns A structured record, ready to be serialised.
 * @example
 * ```ts
 * log(JSON.stringify(sweepRecord(counts)));
 * ```
 */
export function sweepRecord(counts: SweepCounts): Record<string, unknown> {
  const deleted = Object.values(counts).reduce<number>(
    (total, count) => total + (typeof count === "number" ? count : 0),
    0,
  );

  return { message: "signet.sweep.completed", deleted, ...counts };
}

/**
 * Sweeps every expired runtime row, and reports what it verified and deleted.
 *
 * The access token cut-off lags the present by the configured grace period, and is
 * the one instant the command supplies itself. Every other predicate is compared
 * against the database's own transaction time, which is the clock the rows were
 * written by.
 *
 * @param configuration - The owning connection, and how far the access token
 *   cut-off lags the present.
 * @param log - Where the two records go. Injected so the command is testable, and
 *   so a deployment can read out of the Job's logs which identity ran and which
 *   table was growing.
 * @returns How many rows each table gave up.
 * @throws {ConfigError} When the connected role is subject to the tenant isolation
 *   policies, or the schema is not installed. Reporting a clean database on a
 *   credential that can see none of it is the outcome this command exists to make
 *   impossible; a failed job is the one an operator notices.
 * @example
 * ```ts
 * const counts = await runSweepCommand(resolveSweepConfiguration(process.env));
 * ```
 */
export async function runSweepCommand(
  configuration: SweepConfiguration,
  log: (message: string) => void = console.log,
): Promise<SweepCounts> {
  // One connection: the sweep is a handful of serial statements, and a pool would
  // leave idle connections open while the Job waits to exit.
  const handle = createDatabase({
    url: configuration.ownerUrl,
    maxConnections: 1,
  });
  try {
    const verdict = classifySweepIdentity(await observeEnforcement(handle.db));
    if (verdict.outcome !== "healthy") {
      throw new ConfigError(verdict.message);
    }
    log(
      JSON.stringify({
        message: "signet.sweep.identity-verified",
        role: verdict.role,
      }),
    );

    const counts = await sweepExpiredRuntimeRows(handle.db, {
      accessTokensBefore: new Date(
        Date.now() - configuration.accessTokenGraceMs,
      ),
    });

    log(JSON.stringify(sweepRecord(counts)));
    return counts;
  } finally {
    await handle.close();
  }
}
