/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Reading a bearer credential from the `Authorization` header.
 *
 * Shared by the UserInfo endpoint, which is presented an access token, and by the
 * admin API, which is presented a personal access token. They are different
 * credentials with different lifetimes, but the header syntax is one thing and
 * ought to be parsed once - a second copy differing in whether it trimmed the
 * value would make one endpoint accept a token the other rejected.
 *
 * Only the header form is accepted. RFC 6750 also defines a form-encoded body
 * parameter and a query parameter; the query form puts a credential in access logs
 * and browser history, and is deprecated for exactly that reason.
 *
 * Author: John Grimes
 */

/**
 * Extracts a bearer token from an `Authorization` header value.
 *
 * @param authorization - The raw header, if the request carried one.
 * @returns The token, or undefined when the header is absent, is not a bearer
 *   credential, or carries an empty value.
 */
export function bearerToken(
  authorization: string | undefined,
): string | undefined {
  if (
    authorization === undefined ||
    authorization.slice(0, 7).toLowerCase() !== "bearer "
  ) {
    return undefined;
  }
  const value = authorization.slice(7).trim();
  return value.length === 0 ? undefined : value;
}
