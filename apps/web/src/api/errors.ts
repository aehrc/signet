/**
 * How the console understands a refusal.
 *
 * The admin API answers a refusal with a code, a message and - when a request
 * failed validation - one issue per offending field. All three matter to a
 * different part of the UI: the code decides whether to redirect to sign-in, the
 * message is what a person reads, and the issues belong beside the inputs that
 * produced them.
 *
 * The parsing is pure and tested, because the alternative is a form that shows
 * "something went wrong" for a mistyped URL that the server described precisely.
 *
 * Author: John Grimes
 */

/** One field-level problem, as the API reports it. */
export interface ApiIssue {
  /** Dotted path to the field, e.g. `redirectUris.0`. */
  readonly path: string;
  readonly message: string;
}

/** A refusal from the admin API. */
export class ApiError extends Error {
  /** HTTP status, for the cases where the code is not enough. */
  public readonly status: number;
  /** The API's own code: `unauthenticated`, `not_found`, and so on. */
  public readonly code: string;
  public readonly issues: readonly ApiIssue[];
  /**
   * The refusal body as it arrived.
   *
   * A few routes add a field beside the standard three - the sign-in path answers
   * with `totpRequired` when the password was right and a code is needed. Keeping
   * the body means those can be read as data rather than matched on in prose.
   */
  public readonly body: Readonly<Record<string, unknown>>;

  /**
   * @param status - The HTTP status.
   * @param code - The API error code.
   * @param message - The operator-facing message.
   * @param issues - Field-level problems, when there were any.
   * @param body - The refusal body, for the route-specific fields.
   */
  public constructor(
    status: number,
    code: string,
    message: string,
    issues: readonly ApiIssue[] = [],
    body: Readonly<Record<string, unknown>> = {},
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.issues = issues;
    this.body = body;
  }

  /**
   * Reads a boolean flag the route added to the refusal.
   *
   * @param name - The field to read.
   */
  public flag(name: string): boolean {
    return this.body[name] === true;
  }
}

/**
 * Builds an {@link ApiError} from a response body.
 *
 * Tolerant of a body that is not the expected shape: a proxy returning an HTML
 * error page, or a crash producing plain text, must still surface as a readable
 * message rather than as a parse failure inside an error handler.
 *
 * @param status - The HTTP status.
 * @param body - Whatever the response body parsed to, if it parsed at all.
 */
export function toApiError(status: number, body: unknown): ApiError {
  const record =
    typeof body === "object" && body !== null
      ? (body as Record<string, unknown>)
      : {};

  const code = typeof record["error"] === "string" ? record["error"] : "error";
  const message =
    typeof record["message"] === "string"
      ? record["message"]
      : `The server answered ${String(status)}`;

  const issues = Array.isArray(record["issues"])
    ? record["issues"].filter(
        (issue): issue is ApiIssue =>
          typeof issue === "object" &&
          issue !== null &&
          typeof (issue as ApiIssue).path === "string" &&
          typeof (issue as ApiIssue).message === "string",
      )
    : [];

  return new ApiError(status, code, message, issues, record);
}

/**
 * Indexes issues by the field they concern.
 *
 * The first issue for a field wins, because a form shows one message per input and
 * the first is the one the server considered most immediate.
 *
 * @param error - The refusal, or anything else that was thrown.
 */
export function issuesByField(error: unknown): Record<string, string> {
  if (!(error instanceof ApiError)) {
    return {};
  }
  const byField: Record<string, string> = {};
  for (const issue of error.issues) {
    byField[issue.path] ??= issue.message;
  }
  return byField;
}

/**
 * The sentence to show for a failure.
 *
 * Every path returns something readable, including the case where what was thrown
 * is not an error at all - an unhandled rejection inside a mutation should still
 * produce a message rather than "undefined".
 *
 * @param error - The value that was thrown.
 */
export function describeError(error: unknown): string {
  if (error instanceof ApiError) {
    return error.message;
  }
  if (error instanceof Error && error.message.length > 0) {
    return error.message;
  }
  return "Something went wrong. Try again, or check the server logs.";
}

/**
 * Whether a failure means the caller is not signed in.
 *
 * Used to send the browser back to the sign-in page rather than showing an error
 * on a page it cannot populate. A 403 deliberately does not count: the person *is*
 * signed in and simply lacks the authority, and signing them out would be an
 * unhelpful answer to "you may not do that".
 *
 * @param error - The value that was thrown.
 */
export function isUnauthenticated(error: unknown): boolean {
  return error instanceof ApiError && error.status === 401;
}
