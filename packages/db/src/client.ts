import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";

/** Options for opening a Signet database connection. */
export interface DatabaseOptions {
  /** Postgres connection string. */
  readonly url: string;
  /** Maximum pooled connections. */
  readonly maxConnections?: number;
}

/** A Drizzle database handle bound to the Signet schema. */
export type Database = ReturnType<typeof createDatabase>["db"];

/**
 * Opens a pooled Postgres connection and wraps it with Drizzle.
 *
 * The caller owns the returned `close` function; the OAuth endpoints share a
 * single instance for the process lifetime.
 *
 * @param options - Connection settings.
 */
export function createDatabase(options: DatabaseOptions): {
  db: ReturnType<typeof drizzle>;
  close: () => Promise<void>;
} {
  const sql = postgres(options.url, {
    max: options.maxConnections ?? 10,
    // Signet stores no cleartext secrets, but connection errors must never
    // surface credentials into logs.
    onnotice: () => {},
  });

  return {
    db: drizzle(sql),
    close: async () => {
      await sql.end();
    },
  };
}
