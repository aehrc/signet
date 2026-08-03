/**
 * Migrates the test database once, before any test worker starts.
 *
 * See `./schemaReady.ts` for why this is not done lazily. Skipped entirely when no
 * test database is configured, which is the case for a developer running only the
 * unit suites: the integration files check the same variable and skip themselves.
 */

import { createDatabase } from "../client.js";
import { applyMigrationsWithLock } from "../migrations.js";
import { prepareRowLevelSecurityFixtures } from "./rlsRole.js";
import { markTestSchemaReady } from "./schemaReady.js";

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
    markTestSchemaReady();
  } finally {
    await handle.close();
  }
}
