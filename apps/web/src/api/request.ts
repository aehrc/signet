/**
 * The one fetch in the browser.
 *
 * Both surfaces use it: the console's admin API and the end-user pages' issuer-scoped
 * API. They differ in one thing only — the shape of a refusal body, because the admin API
 * answers with `error` and `message` while the OAuth endpoints answer with `error` and
 * `error_description`, as RFC 6749 requires. That difference is a parameter rather than a
 * second copy of the request logic.
 *
 * Three properties hold for every request as a result: the session cookie is always sent,
 * a refusal always arrives as an `ApiError` carrying the server's own message, and no
 * caller has to check `response.ok`.
 *
 * There is no bearer token here. Both surfaces authenticate with an httpOnly cookie,
 * which JavaScript cannot read — that is the point of it — so `credentials:
 * "same-origin"` is the whole of the credential handling. The one exception is the
 * developer portal's tracking token, which is not a session and is passed explicitly.
 */

import { toApiError } from "./errors.js";

/** What a request may carry. */
export interface RequestOptions {
  readonly method?: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
  /** Serialised as JSON. Omit for a request with no body. */
  readonly body?: unknown;
  /** Aborts the request; supplied by TanStack Query. */
  readonly signal?: AbortSignal;
  /** Extra headers. Used for the portal's tracking token and nothing else. */
  readonly headers?: Readonly<Record<string, string>>;
  /**
   * Reshapes a refusal body before it becomes an `ApiError`.
   *
   * The default passes it through, which is right for the admin API. The end-user API
   * supplies one that lifts `error_description` into `message`.
   */
  readonly normaliseError?: (body: unknown) => unknown;
}

/**
 * Makes a request and returns its parsed body.
 *
 * @param path - An absolute path on this origin.
 * @param options - The method, body, headers and error normalisation.
 * @throws {ApiError} For any non-2xx response, carrying the server's message.
 * @returns The parsed JSON body, or undefined for a `204`.
 */
export async function requestJson<T>(
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const response = await fetch(path, {
    method: options.method ?? "GET",
    // Same-origin rather than `include`: both APIs are served by the same process as
    // this bundle, and a cross-origin credentialed request is not something the UI
    // should be able to make by accident.
    credentials: "same-origin",
    headers: {
      accept: "application/json",
      ...(options.body === undefined
        ? {}
        : { "content-type": "application/json" }),
      ...options.headers,
    },
    ...(options.body === undefined
      ? {}
      : { body: JSON.stringify(options.body) }),
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });

  if (response.status === 204) {
    return undefined as T;
  }

  // Parsed before the status is inspected, because a refusal's body is where the message
  // and the field issues are. A body that is not JSON at all yields undefined and
  // `toApiError` falls back to describing the status.
  const body: unknown = await response.json().catch(() => {});

  if (!response.ok) {
    throw toApiError(
      response.status,
      options.normaliseError === undefined
        ? body
        : options.normaliseError(body),
    );
  }
  return body as T;
}
