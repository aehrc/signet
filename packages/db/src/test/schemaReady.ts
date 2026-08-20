/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Where the test schema is migrated, and how the suites know.
 *
 * Migrations are DDL, and DDL takes exclusive table locks. Applying them lazily
 * from whichever test file happened to run first meant one suite altering tables
 * while another held row locks on them - which Postgres resolves by killing one of
 * the two, and which surfaced as a deadlock in an unrelated assertion. The schema
 * is therefore migrated exactly once, before any test file is imported, by the
 * preload in `./preload.ts`.
 *
 * `bun test` runs every file in one process, sequentially, so that ordering is now
 * guaranteed rather than merely arranged - but the two sources of overlap that
 * caused the deadlock have not gone anywhere: a second `bun test` against the same
 * database, and a `bun run dev` server holding rows in it. What has changed is that
 * they are outside this process rather than inside it, which is why the advisory
 * lock in `../migrations.ts` is still what makes it safe.
 *
 * The signal is an environment variable, which the preload sets and every suite in
 * the same process reads. A file run some other way - `bun test path/to/one.test.ts`
 * from inside a package, where Bun finds no `bunfig.toml` and so runs no preload -
 * sees it unset and migrates for itself.
 *
 * Author: John Grimes
 */

/** Set by the preload once the schema has been migrated. */
export const TEST_SCHEMA_READY_VARIABLE = "SIGNET_TEST_SCHEMA_READY";

/**
 * Whether something has already migrated the test database this run.
 *
 * @param env - The environment to read. Defaults to the process's own.
 */
export function isTestSchemaReady(
  env: Readonly<Record<string, string | undefined>> = process.env,
): boolean {
  return env[TEST_SCHEMA_READY_VARIABLE] === "1";
}

/** Records that the schema has been migrated, for the suites to read. */
export function markTestSchemaReady(): void {
  process.env[TEST_SCHEMA_READY_VARIABLE] = "1";
}
