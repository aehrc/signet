/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * What one application's database connections are doing, seen from another.
 *
 * A transaction held across an outbound HTTP request holds a pooled connection for
 * as long as the other end takes to answer, which on a federation path means handing
 * a denial-of-service surface to a server the deployment does not control. Asserting
 * that no such transaction exists cannot be done from inside the process holding it:
 * the only witness is the database, and it has to be asked from a second connection
 * while the request is in flight.
 *
 * `pg_stat_activity` reports every backend, but nulls `state` and `query` for
 * backends belonging to another role - so the probe connects as the same role as the
 * application it is observing. It filters on `application_name` rather than on the
 * role, because every suite in the run connects as that same role, as does a second
 * `bun test` against the same database: without the filter, somebody else's open
 * transaction would fail this suite's assertion.
 *
 * Lives here, and is exported from the package, for the reason `privilegeProbe.ts`
 * is: `apps/server` needs it and cannot write raw SQL, because only this package
 * depends on Drizzle.
 *
 * Author: John Grimes
 */

import { sql } from "drizzle-orm";

import { createDatabase } from "../client.js";

/** A connection that observes other backends. */
export interface ActivityProbe {
  /**
   * The states of one application's backends, excluding the probe's own.
   *
   * `idle in transaction` is the one that matters: it means a transaction is open
   * and nothing is running in it, which is exactly what a connection blocked on an
   * outbound HTTP call looks like from the database's point of view.
   *
   * @param applicationName - What the observed connections call themselves.
   * @returns One entry per backend, in no particular order.
   */
  readonly statesOf: (applicationName: string) => Promise<readonly string[]>;
  readonly close: () => Promise<void>;
}

/** One `pg_stat_activity` row, reduced to what the probe reads. */
interface ActivityRow {
  readonly state: string | null;
}

/**
 * Opens a probe.
 *
 * @param url - The connection to observe from. Must name the same role as the
 *   application being observed, or `state` comes back null for every row.
 * @returns The probe, which the caller closes.
 * @example
 * ```ts
 * const probe = createActivityProbe(servingRoleUrl(testDatabaseUrl));
 * expect(await probe.statesOf(stack.applicationName)).not.toContain(
 *   "idle in transaction",
 * );
 * await probe.close();
 * ```
 */
export function createActivityProbe(url: string): ActivityProbe {
  const handle = createDatabase({
    url,
    maxConnections: 1,
    applicationName: "signet-activity-probe",
  });

  return {
    statesOf: async (applicationName) => {
      const rows = (await handle.db.execute(
        sql`
          select state from pg_stat_activity
          where application_name = ${applicationName}
            and pid <> pg_backend_pid()
        `,
      )) as unknown as readonly ActivityRow[];
      return rows.map((row) => row.state ?? "unknown");
    },
    close: handle.close,
  };
}
