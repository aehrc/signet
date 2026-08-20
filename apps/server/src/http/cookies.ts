/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Reading a cookie from a request.
 *
 * Shared by the console's session and the end user's, which are different credentials
 * with different lifetimes and different path scopes - but one header syntax, and it
 * ought to be parsed once. A second copy differing in whether it trimmed the value, or
 * which of two same-named cookies it took, would make one surface accept a cookie the
 * other rejected.
 *
 * Written by hand rather than with a parser because the header comes from an untrusted
 * client: a duplicate name, a missing `=` and a value containing `=` all have to behave
 * predictably.
 *
 * Author: John Grimes
 */

/**
 * Reads one cookie from a `Cookie` header.
 *
 * The *first* occurrence of a name wins, matching what browsers send for the most
 * specific path - which matters here, because an end user's session cookie is scoped to
 * an endpoint's path and a browser holding two of them sends the narrower one first.
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
 * Builds a `Set-Cookie` value for a session credential.
 *
 * Every attribute is a security decision, so they are set here rather than at each call
 * site.
 *
 * `HttpOnly` keeps the value out of reach of any script on the origin, which matters
 * more than usual: the console, the end-user authorization pages and the developer
 * portal share an origin, and one of those renders a client's registered name and logo.
 * `SameSite=Lax` stops a cross-site form post acting as the signed-in caller while still
 * allowing the ordinary case of following a link in. `Secure` is decided from the
 * deployment's own public URL rather than from the request, because a request arriving
 * over HTTP at a service published over HTTPS has been through a proxy, and the proxy's
 * scheme is not the one the browser used.
 *
 * @param name - The cookie's name.
 * @param value - The credential, or an empty string to clear it.
 * @param options - How the cookie should be scoped.
 * @param options.path - The path the cookie is sent for. `/` for the console; an
 *   endpoint's own path for an end user, so a session on one endpoint is not presented
 *   to another.
 * @param options.secure - Whether to mark the cookie `Secure`.
 * @param options.maxAgeSeconds - Lifetime in seconds. Zero clears the cookie.
 */
export function sessionCookieHeader(
  name: string,
  value: string,
  options: {
    readonly path: string;
    readonly secure: boolean;
    readonly maxAgeSeconds: number;
  },
): string {
  return [
    `${name}=${value}`,
    `Path=${options.path}`,
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${String(options.maxAgeSeconds)}`,
    ...(options.secure ? ["Secure"] : []),
  ].join("; ");
}

/**
 * Whether cookies should carry `Secure`, given the deployment's public URL.
 *
 * @param publicUrl - `SIGNET_PUBLIC_URL`, as resolved by the configuration.
 */
export function cookiesAreSecure(publicUrl: string): boolean {
  return publicUrl.startsWith("https:");
}
