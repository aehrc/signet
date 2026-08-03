/**
 * The console session cookie.
 *
 * Every attribute here is a security decision, so they are set in one place and
 * asserted in tests rather than spelled out at each call site.
 *
 * `HttpOnly` keeps the session out of reach of any script on the origin, which
 * matters more than usual: the console and the end-user authorization pages are
 * served from the same origin, and one of those renders a client's registered name
 * and logo. `SameSite=Lax` is what stops a cross-site form post from acting as the
 * signed-in operator, while still allowing the ordinary case of following a link
 * into the console. `Secure` is derived from the deployment's own public URL rather
 * than from the request, because a request arriving over HTTP at a service that is
 * published over HTTPS has been through a proxy, and the proxy's scheme is not the
 * one the browser used.
 *
 * `Path=/` rather than `/api`: the cookie is read by the API and cleared by the
 * console, and scoping it to the API path would leave a cookie the console cannot
 * expire.
 */

/** Name of the console session cookie. */
export const SESSION_COOKIE_NAME = "signet_session";

/** How long a console session lasts, in seconds. Twelve hours. */
export const SESSION_TTL_SECONDS = 43_200;

/**
 * Reads one cookie from a `Cookie` header.
 *
 * Written by hand rather than with a parser because the header is a request
 * header from an untrusted client: a duplicate name, a missing `=` and a value
 * containing `=` all have to behave predictably. The *first* occurrence wins,
 * matching what browsers send for the most specific path.
 *
 * @param header - The raw `Cookie` header, if the request had one.
 * @param name - The cookie to read.
 * @returns The value, or undefined when the cookie is absent or empty.
 */
export function readCookie(
  header: string | undefined,
  name: string,
): string | undefined {
  if (header === undefined) {
    return undefined;
  }

  for (const pair of header.split(";")) {
    const separator = pair.indexOf("=");
    if (separator === -1) {
      continue;
    }
    if (pair.slice(0, separator).trim() !== name) {
      continue;
    }
    const value = pair.slice(separator + 1).trim();
    return value.length === 0 ? undefined : value;
  }
  return undefined;
}

/**
 * Whether cookies should carry `Secure`, given the deployment's public URL.
 *
 * @param publicUrl - `SIGNET_PUBLIC_URL`, as resolved by the configuration.
 */
export function cookiesAreSecure(publicUrl: string): boolean {
  return publicUrl.startsWith("https:");
}

/**
 * Builds the `Set-Cookie` value that opens a session.
 *
 * @param value - The session token. Stored only as a digest server-side.
 * @param options - How the cookie should be scoped.
 * @param options.secure - Whether to mark the cookie `Secure`.
 * @param options.maxAgeSeconds - Lifetime, defaulting to
 *   {@link SESSION_TTL_SECONDS}.
 */
export function sessionCookie(
  value: string,
  options: { readonly secure: boolean; readonly maxAgeSeconds?: number },
): string {
  const maxAge = options.maxAgeSeconds ?? SESSION_TTL_SECONDS;
  return [
    `${SESSION_COOKIE_NAME}=${value}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${String(maxAge)}`,
    ...(options.secure ? ["Secure"] : []),
  ].join("; ");
}

/**
 * Builds the `Set-Cookie` value that ends a session.
 *
 * Every attribute except the lifetime matches {@link sessionCookie}: a browser
 * only replaces a cookie whose name, path and domain agree, so an expiry that
 * differed in `Path` would leave the old cookie in place.
 *
 * @param options - How the cookie should be scoped.
 * @param options.secure - Whether to mark the cookie `Secure`.
 */
export function clearedSessionCookie(options: {
  readonly secure: boolean;
}): string {
  return [
    `${SESSION_COOKIE_NAME}=`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    "Max-Age=0",
    ...(options.secure ? ["Secure"] : []),
  ].join("; ");
}
