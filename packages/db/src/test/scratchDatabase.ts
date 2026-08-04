/**
 * An empty database, for the suite that has to observe an unmigrated one.
 *
 * One of the startup check's four outcomes is that the covered tables do not
 * exist, and it is the outcome an operator hits first: a fresh deployment whose
 * migration has not run. Asserting it requires a database on which nothing has
 * been created, and the shared test database cannot be it - other workers are
 * using the tables, so dropping them to observe their absence would break every
 * suite running beside this one.
 *
 * So the suite creates its own, uses it, and drops it. `create database` is DDL
 * outside any transaction and takes a brief lock on the template, which is why it
 * is done once per suite rather than per assertion.
 *
 * Author: John Grimes
 */

import { sql } from "drizzle-orm";

import type { Executor } from "../repositories/executor.js";

/** Quotes an identifier, doubling any embedded quote. */
function quoted(name: string): string {
  return `"${name.replaceAll('"', '""')}"`;
}

/**
 * Creates an empty database.
 *
 * @param db - A connection with authority to create databases, which for a
 *   throwaway test database is the identity the developer configured.
 * @param name - The name to create. Unique per worker, since Vitest runs files in
 *   parallel against one server.
 * @throws {Error} When the statement fails, including when the database already
 *   exists - a leftover from an interrupted run holds a schema this suite would
 *   then wrongly report as absent.
 */
export async function createScratchDatabase(
  db: Executor,
  name: string,
): Promise<void> {
  await db.execute(sql.raw(`create database ${quoted(name)}`));
}

/**
 * Drops a scratch database.
 *
 * `with (force)` so a connection the suite failed to close does not leave the
 * database behind, which would make the next run of the suite fail on creation.
 *
 * @param db - A connection with authority to drop databases.
 * @param name - The name to drop. Absent is not an error, so this is safe in a
 *   teardown that runs after a failed setup.
 */
export async function dropScratchDatabase(
  db: Executor,
  name: string,
): Promise<void> {
  await db.execute(
    sql.raw(`drop database if exists ${quoted(name)} with (force)`),
  );
}
