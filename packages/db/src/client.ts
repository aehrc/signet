import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";

import type { Executor } from "./repositories/executor.js";

/** Options for opening a Signet database connection. */
export interface DatabaseOptions {
  /** Postgres connection string. */
  readonly url: string;
  /** Maximum pooled connections. */
  readonly maxConnections?: number;
}

/**
 * A Drizzle handle, of exactly the type every repository accepts.
 *
 * Drizzle is deliberately constructed WITHOUT its `schema` option. Passing the
 * schema would produce a differently parameterised type that is not assignable
 * to `Executor`, forcing a cast at every repository call site — the kind of
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
  const sql = postgres(options.url, {
    max: options.maxConnections ?? 10,
    // Connection and notice output must never surface the credentials embedded
    // in the connection URL.
    onnotice: () => {},
  });

  return {
    db: drizzle(sql),
    close: async () => {
      await sql.end();
    },
  };
}
