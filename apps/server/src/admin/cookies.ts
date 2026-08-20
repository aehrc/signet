/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The console session cookie.
 *
 * The attributes and the parsing live in `../http/cookies.js`, shared with the end
 * user's session; what is here is what is specific to the console: the cookie's name, its
 * lifetime, and the fact that it is scoped to the whole application rather than to one
 * endpoint's path.
 *
 * `Path=/` rather than `/api`: the cookie is read by the API and cleared by the console,
 * and scoping it to the API path would leave a cookie the console cannot expire.
 *
 * Author: John Grimes
 */

import { sessionCookieHeader } from "../http/cookies.js";

/** Name of the console session cookie. */
export const SESSION_COOKIE_NAME = "signet_session";

/** How long a console session lasts, in seconds. Twelve hours. */
export const SESSION_TTL_SECONDS = 43_200;

/** The path the console's cookie is sent for. */
const CONSOLE_COOKIE_PATH = "/";

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
  return sessionCookieHeader(SESSION_COOKIE_NAME, value, {
    path: CONSOLE_COOKIE_PATH,
    secure: options.secure,
    maxAgeSeconds: options.maxAgeSeconds ?? SESSION_TTL_SECONDS,
  });
}

/**
 * Builds the `Set-Cookie` value that ends a session.
 *
 * Every attribute except the lifetime matches {@link sessionCookie}: a browser only
 * replaces a cookie whose name, path and domain agree, so an expiry that differed in
 * `Path` would leave the old cookie in place.
 *
 * @param options - How the cookie should be scoped.
 * @param options.secure - Whether to mark the cookie `Secure`.
 */
export function clearedSessionCookie(options: {
  readonly secure: boolean;
}): string {
  return sessionCookieHeader(SESSION_COOKIE_NAME, "", {
    path: CONSOLE_COOKIE_PATH,
    secure: options.secure,
    maxAgeSeconds: 0,
  });
}

export { cookiesAreSecure, readCookie } from "../http/cookies.js";
