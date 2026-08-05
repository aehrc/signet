/**
 * Migrates the test database once, before any test file is loaded.
 *
 * See `./schemaReady.ts` for why this is not done lazily. Skipped entirely when no
 * test database is configured, which is the case for a developer running only the
 * unit suites: the integration files check the same variable and skip themselves.
 *
 * Registered as `preload` under `[test]` in the repository's `bunfig.toml`, so it
 * runs once per `bun test` invocation, before the first test file is imported. Bun
 * resolves `bunfig.toml` from the working directory and does not search upwards,
 * so `bun test` run from inside a package gets no preload - which is why the
 * integration files still migrate for themselves when the flag is unset rather
 * than depending on this having run.
 *
 * Author: John Grimes
 */

import { createDatabase } from "../client.js";
import { applyMigrationsWithLock } from "../migrations.js";
import { markTestSchemaReady } from "./schemaReady.js";
import { prepareServingRole } from "./servingRole.js";

const url = process.env["SIGNET_TEST_DATABASE_URL"];

if (url !== undefined && url.trim().length > 0) {
  const handle = createDatabase({ url, maxConnections: 1 });
  try {
    // Still under the advisory lock: two `bun test` invocations against the same
    // database are a thing a developer does, and the lock is what makes the
    // second wait rather than interleave.
    await applyMigrationsWithLock(handle.db);
    // The role every suite connects as, and its grants. Created here rather than
    // by whichever test file got there first, for the same reason again: a
    // `create role` racing a `grant ... on all tables` is a catalogue write that
    // should not interleave with the suites it exists to enable.
    //
    // This connection - the owning identity, which the policies exempt - is used
    // for the schema and for nothing else. Every suite derives its own connection
    // from the same URL by swapping the credential, so what the suites exercise is
    // a role the policies bind. That is what makes them evidence rather than
    // decoration: with the owning identity they would pass whether or not a single
    // policy were installed.
    await prepareServingRole(handle.db);
    markTestSchemaReady();
  } finally {
    await handle.close();
  }
}
