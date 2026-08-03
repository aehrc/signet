/**
 * Recognising the database errors that are part of the domain.
 *
 * Two constraint violations in the Signet schema are load-bearing security
 * checks rather than faults: the `jti_replay` primary key rejecting a replayed
 * client assertion, and the unique index on `(endpoint_id, version)` rejecting
 * two policy versions allocated concurrently. A caller has to be able to tell
 * those apart from a database that is broken or unreachable — "the assertion has
 * been seen before" and "the database is down" call for opposite responses, and
 * a bare driver error conflates them.
 *
 * The predicates here are structural rather than `instanceof PostgresError`, so
 * that they hold for an error that has crossed a pooling or serialisation
 * boundary, and so they can be unit tested without a driver.
 *
 * @see https://www.postgresql.org/docs/current/errcodes-appendix.html
 */

/** SQLSTATE for `unique_violation`. */
export const UNIQUE_VIOLATION = "23505";

/** SQLSTATE for `foreign_key_violation`. */
export const FOREIGN_KEY_VIOLATION = "23503";

/** SQLSTATE for `serialization_failure`, which a caller may safely retry. */
export const SERIALIZATION_FAILURE = "40001";

/** SQLSTATE for `deadlock_detected`, which a caller may safely retry. */
export const DEADLOCK_DETECTED = "40P01";

/** Reads a Postgres SQLSTATE from an unknown thrown value. */
export function sqlStateOf(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null) {
    return undefined;
  }

  const code: unknown = (error as { code?: unknown }).code;
  return typeof code === "string" ? code : undefined;
}

/**
 * Whether an error is a unique or primary key violation.
 *
 * @param error - The thrown value to inspect.
 * @param constraint - When given, also requires the violated constraint to be
 *   this one, so that a caller waiting on a specific collision is not fooled by
 *   an unrelated one raised by the same statement.
 */
export function isUniqueViolation(
  error: unknown,
  constraint?: string,
): boolean {
  if (sqlStateOf(error) !== UNIQUE_VIOLATION) {
    return false;
  }
  if (constraint === undefined) {
    return true;
  }

  const violated: unknown = (error as { constraint_name?: unknown })
    .constraint_name;
  return violated === constraint;
}

/** Whether an error is a foreign key violation. */
export function isForeignKeyViolation(error: unknown): boolean {
  return sqlStateOf(error) === FOREIGN_KEY_VIOLATION;
}

/**
 * Whether the transaction failed for a reason that retrying can resolve.
 *
 * Distinguishing this matters for the token endpoint: a serialisation failure
 * must not be reported to the client as an authorization refusal, because the
 * request was in fact valid.
 */
export function isRetryableTransactionError(error: unknown): boolean {
  const state = sqlStateOf(error);
  return state === SERIALIZATION_FAILURE || state === DEADLOCK_DETECTED;
}
