/**
 * OAuth 2.0 error responses.
 *
 * Every refusal Signet issues is built here, for two reasons. The response codes
 * are a closed set defined by RFC 6749, and inventing one — or returning
 * `invalid_request` where the spec requires `invalid_client` — breaks client
 * libraries that switch on the value. And the *status* attached to each is not
 * obvious: `invalid_client` is 401, everything else at the token endpoint is
 * 400, and a token endpoint must never answer with a redirect.
 *
 * The descriptions are for a developer reading a log, not for an end user, and
 * they deliberately never restate the credential that was rejected.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */

/** Error codes the authorization endpoint may return. RFC 6749 §4.1.2.1. */
export type AuthorizeErrorCode =
  | "invalid_request"
  | "unauthorized_client"
  | "access_denied"
  | "unsupported_response_type"
  | "invalid_scope"
  | "server_error"
  | "temporarily_unavailable";

/** Error codes the token endpoint may return. RFC 6749 §5.2. */
export type TokenErrorCode =
  | "invalid_request"
  | "invalid_client"
  | "invalid_grant"
  | "unauthorized_client"
  | "unsupported_grant_type"
  | "invalid_scope";

/** A serialised OAuth error body. */
export interface OAuthErrorBody {
  readonly error: string;
  readonly error_description?: string;
}

/**
 * Builds an error body, omitting the description rather than emitting an empty
 * one.
 *
 * @param code - The RFC-defined error code.
 * @param description - Developer-facing detail. Never a credential.
 */
export function oauthErrorBody(
  code: string,
  description?: string,
): OAuthErrorBody {
  return {
    error: code,
    ...(description === undefined ? {} : { error_description: description }),
  };
}

/**
 * The HTTP status for a token endpoint error.
 *
 * `invalid_client` is 401 because it is an authentication failure, and RFC 6749
 * §5.2 requires it. Every other code is a well-formed request that was refused,
 * which is 400. Answering `invalid_client` with 400 is a common bug that makes
 * clients retry with the same broken credential instead of stopping.
 */
export function statusForTokenError(code: TokenErrorCode): 400 | 401 {
  return code === "invalid_client" ? 401 : 400;
}

/**
 * Builds the redirect an authorization endpoint refusal produces.
 *
 * `state` is echoed back when the request carried one — a client that cannot
 * correlate the error with its own request will usually surface it as a blank
 * page rather than as a message.
 *
 * The error is placed in the query string, not the fragment: `response_type` is
 * always `code` here, and RFC 6749 §4.1.2.1 puts a code-flow error in the query.
 *
 * @param redirectUri - An already-validated registered redirect URI. Passing an
 *   unvalidated one would turn this function into an open redirector.
 * @param code - The RFC-defined error code.
 * @param description - Developer-facing detail.
 * @param state - The `state` from the request, if it had one.
 */
export function authorizeErrorRedirect(
  redirectUri: string,
  code: AuthorizeErrorCode,
  description?: string,
  state?: string,
): string {
  const url = new URL(redirectUri);
  url.searchParams.set("error", code);
  if (description !== undefined) {
    url.searchParams.set("error_description", description);
  }
  if (state !== undefined) {
    url.searchParams.set("state", state);
  }
  return url.toString();
}
