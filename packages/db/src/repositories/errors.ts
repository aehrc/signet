/**
 * Recognising the database errors that are part of the domain.
 *
 * Two constraint violations in the Signet schema are load-bearing security
 * checks rather than faults: the `jti_replay` primary key rejecting a replayed
 * client assertion, and the unique index on `(endpoint_id, version)` rejecting
 * two policy versions allocated concurrently. A caller has to be able to tell
 * those apart from a database that is broken or unreachable - "the assertion has
 * been seen before" and "the database is down" call for opposite responses, and
 * a bare driver error conflates them.
 *
 * The predicates here are structural rather than `instanceof PostgresError`, so
 * that they hold for an error that has crossed a pooling or serialisation
 * boundary, and so they can be unit tested without a driver.
 *
 * @see https://www.postgresql.org/docs/current/errcodes-appendix.html
 *
 * Author: John Grimes
 */

/** SQLSTATE for `unique_violation`. */
export const UNIQUE_VIOLATION = "23505";

/** SQLSTATE for `foreign_key_violation`. */
export const FOREIGN_KEY_VIOLATION = "23503";

/** SQLSTATE for `serialization_failure`, which a caller may safely retry. */
export const SERIALIZATION_FAILURE = "40001";

/** SQLSTATE for `deadlock_detected`, which a caller may safely retry. */
export const DEADLOCK_DETECTED = "40P01";

/**
 * How far down a `cause` chain to look for a SQLSTATE.
 *
 * Drizzle wraps a driver error in a `DrizzleQueryError` carrying the original as
 * `cause`, and a pool or a retry helper may wrap it again. Three levels covers
 * every wrapper in this stack; a bound rather than an unbounded walk means a
 * self-referential `cause` cannot spin.
 */
const MAX_CAUSE_DEPTH = 3;

/** The fields a Postgres driver error carries that this module reads. */
interface DriverError {
  readonly code: string;
  readonly constraint_name?: unknown;
}

/**
 * Finds the driver error inside whatever was thrown.
 *
 * Walks the `cause` chain, because the error a caller catches is rarely the error
 * the driver raised: the query layer wraps it to attach the statement. A predicate
 * that only looked at the outermost value would report "not a unique violation"
 * for every unique violation this application can actually observe, which is the
 * kind of bug that turns a 409 into a 500.
 *
 * Both the SQLSTATE and the constraint name are then read from the *same* object,
 * so a caller asking about a specific constraint cannot be answered from one error
 * and refused by another.
 */
function driverErrorOf(error: unknown): DriverError | undefined {
  let candidate: unknown = error;
  for (let depth = 0; depth <= MAX_CAUSE_DEPTH; depth += 1) {
    if (typeof candidate !== "object" || candidate === null) {
      return undefined;
    }
    const code: unknown = (candidate as { code?: unknown }).code;
    if (typeof code === "string") {
      return candidate as DriverError;
    }
    candidate = (candidate as { cause?: unknown }).cause;
  }
  return undefined;
}

/** Reads a Postgres SQLSTATE from an unknown thrown value. */
export function sqlStateOf(error: unknown): string | undefined {
  return driverErrorOf(error)?.code;
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
  const driver = driverErrorOf(error);
  if (driver?.code !== UNIQUE_VIOLATION) {
    return false;
  }
  return constraint === undefined || driver.constraint_name === constraint;
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
