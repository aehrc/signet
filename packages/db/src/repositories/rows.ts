/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Turning query results into values the rest of the code can rely on.
 *
 * `noUncheckedIndexedAccess` makes every `rows[0]` a `T | undefined`, which is
 * correct: a `RETURNING` clause really can come back empty when the predicate
 * matched nothing. The two helpers here draw the distinction explicitly, so that
 * "this insert must have produced a row" and "this update may legitimately have
 * matched none" are different statements at the call site rather than the same
 * non-null assertion twice.
 *
 * Author: John Grimes
 */

/**
 * Thrown when a statement that must produce exactly one row produced none.
 *
 * This is a broken invariant rather than a user-facing condition - an
 * unconditional `INSERT ... RETURNING` that yields nothing means the schema and
 * this code disagree - so it is deliberately not part of any repository's return
 * union. Callers should not be tempted to handle it.
 */
export class RepositoryInvariantError extends Error {
  /** @param message - What was expected, and of which statement. */
  public constructor(message: string) {
    super(message);
    this.name = "RepositoryInvariantError";
  }
}

/**
 * Takes the single row a statement was required to produce.
 *
 * @param rows - The `RETURNING` result.
 * @param description - Named in the error, e.g. `insert into endpoints`.
 * @throws {RepositoryInvariantError} When no row was returned.
 */
export function requireRow<T>(rows: readonly T[], description: string): T {
  const row = rows[0];
  if (row === undefined) {
    throw new RepositoryInvariantError(`${description} returned no rows`);
  }
  return row;
}

/**
 * Takes the first row, if the statement produced one.
 *
 * Used where an empty result is a real outcome: a lookup that found nothing, or
 * a conditional update whose guard did not hold.
 */
export function firstRow<T>(rows: readonly T[]): T | undefined {
  return rows[0];
}
