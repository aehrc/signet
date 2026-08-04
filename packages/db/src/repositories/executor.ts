/**
 * The database handle repository functions accept.
 *
 * Every function here takes an {@link Executor} rather than the concrete
 * `Database` from `../client.js`, because a Drizzle transaction and a Drizzle
 * connection expose the same query surface but are different types. Typing
 * against the common supertype means one implementation serves both, so a
 * caller can compose several repository calls into a single transaction without
 * a parallel set of transaction-only functions - and, more to the point, so the
 * security-bearing operations in this directory can be *forced* into a
 * transaction by their own implementations.
 *
 * Author: John Grimes
 */

import type { PgDatabase } from "drizzle-orm/pg-core";
import type { PostgresJsQueryResultHKT } from "drizzle-orm/postgres-js";

/**
 * A Drizzle connection or transaction against the Signet schema.
 *
 * Relational queries (`db.query.*`) are deliberately not part of this type:
 * they require the schema to have been passed to `drizzle()`, and every function
 * in this directory builds its predicates explicitly so that the tenant
 * predicate is visible at the call site.
 */
export type Executor = PgDatabase<
  PostgresJsQueryResultHKT,
  Record<string, never>
>;
