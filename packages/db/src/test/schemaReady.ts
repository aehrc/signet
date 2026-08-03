/**
 * Where the test schema is migrated, and how the workers know.
 *
 * Migrations are DDL, and DDL takes exclusive table locks. Applying them lazily
 * from whichever test file happened to run first meant a worker altering tables
 * while another worker held row locks on them — which Postgres resolves by killing
 * one of the two, and which surfaced as a deadlock in an unrelated assertion. The
 * schema is therefore migrated exactly once, before any worker starts, by the
 * global setup in `./globalSetup.ts`.
 *
 * The signal is an environment variable rather than Vitest's `provide`/`inject`,
 * because the setup runs in the main process and the workers are spawned after it
 * completes: they inherit the variable, and a suite run outside Vitest — a single
 * file invoked directly — still migrates for itself.
 */

/** Set by the global setup once the schema has been migrated. */
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

/** Records that the schema has been migrated, for the workers to read. */
export function markTestSchemaReady(): void {
  process.env[TEST_SCHEMA_READY_VARIABLE] = "1";
}
