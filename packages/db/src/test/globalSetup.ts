/**
 * Migrates the test database once, before any test worker starts.
 *
 * See `./schemaReady.ts` for why this is not done lazily. Skipped entirely when no
 * test database is configured, which is the case for a developer running only the
 * unit suites: the integration files check the same variable and skip themselves.
 *
 * Author: John Grimes
 */

import { createDatabase } from "../client.js";
import { applyMigrationsWithLock } from "../migrations.js";
import { prepareRowLevelSecurityFixtures } from "./rlsRole.js";
import { markTestSchemaReady } from "./schemaReady.js";
import { prepareServingRole } from "./servingRole.js";

/** Vitest's global setup entry point. */
export default async function setup(): Promise<void> {
  const url = process.env["SIGNET_TEST_DATABASE_URL"];
  if (url === undefined || url.trim().length === 0) {
    return;
  }

  const handle = createDatabase({ url, maxConnections: 1 });
  try {
    // Still under the advisory lock: two `bun run test` invocations against the
    // same database are a thing a developer does, and the lock is what makes the
    // second wait rather than interleave.
    await applyMigrationsWithLock(handle.db);
    // The row-level security suite's role and policies are DDL too, and for the
    // same reason they must not be created while other workers are running.
    await prepareRowLevelSecurityFixtures(handle.db);
    // The role the suites will connect as, and its grants. Created here rather
    // than by whichever worker got there first, for the same reason again: a
    // `create role` racing a `grant ... on all tables` is a catalogue write that
    // should not interleave with the suites it exists to enable.
    //
    // Nothing connects as it yet - every suite still uses the owning identity,
    // which the policies exempt. Switching them over is what makes the suite
    // evidence rather than decoration, and it is deliberately a later step: the
    // role and its grants land first, with the suite green throughout.
    await prepareServingRole(handle.db);
    markTestSchemaReady();
  } finally {
    await handle.close();
  }
}
