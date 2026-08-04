/**
 * Author: John Grimes
 */

import { sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";

import type { Executor } from "./repositories/executor.js";

/** Options for opening a Signet database connection. */
export interface DatabaseOptions {
  /** Postgres connection string. */
  readonly url: string;
  /** Maximum pooled connections. */
  readonly maxConnections?: number;
  /**
   * What this connection calls itself in `pg_stat_activity`.
   *
   * Ordinary operational hygiene - an operator looking at a busy database should be
   * able to tell Signet's backends from a reporting job's - and it is also what lets
   * a test observe the transactions one particular application is holding while
   * other test workers hold their own.
   */
  readonly applicationName?: string;
}

/**
 * A Drizzle handle, of exactly the type every repository accepts.
 *
 * Drizzle is deliberately constructed WITHOUT its `schema` option. Passing the
 * schema would produce a differently parameterised type that is not assignable
 * to `Executor`, forcing a cast at every repository call site - the kind of
 * friction that eventually gets solved with `as any`. The relational query
 * builder it unlocks (`db.query.*`) is unused: the repositories write their
 * joins explicitly. If that changes, widen `Executor` rather than casting here.
 */
export type Database = Executor;

/** An open connection and the means to close it. */
export interface DatabaseHandle {
  readonly db: Database;
  readonly close: () => Promise<void>;
}

/**
 * Opens a pooled Postgres connection and wraps it with Drizzle.
 *
 * The caller owns the returned `close` function; the OAuth endpoints share a
 * single instance for the process lifetime.
 *
 * @param options - Connection settings.
 */
export function createDatabase(options: DatabaseOptions): DatabaseHandle {
  const connection = postgres(options.url, {
    max: options.maxConnections ?? 10,
    // Connection and notice output must never surface the credentials embedded
    // in the connection URL.
    onnotice: () => {},
    ...(options.applicationName === undefined
      ? {}
      : { connection: { application_name: options.applicationName } }),
  });

  return {
    db: drizzle(connection),
    close: async () => {
      await connection.end();
    },
  };
}

/**
 * The cheapest statement that proves a usable connection.
 *
 * Lives here rather than in the server so that the server's readiness probe does
 * not need a direct dependency on Drizzle merely to write `select 1`. Throws on
 * failure, which is what the caller wants to catch: a readiness probe's job is to
 * turn an unreachable database into a 503, and it needs to know.
 *
 * @param db - The connection to test.
 */
export async function pingDatabase(db: Executor): Promise<void> {
  await db.execute(sql`select 1`);
}
