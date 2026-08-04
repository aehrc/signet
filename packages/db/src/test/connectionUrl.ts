/**
 * Deriving one connection URL from another.
 *
 * A developer configures a single variable, `SIGNET_TEST_DATABASE_URL`, naming the
 * identity that owns the schema. Every other connection a suite needs - the
 * serving role the suites run as, a probe role created to be refused, an empty
 * database created to stand in for an unmigrated one - is that URL with one or two
 * components replaced, because host, port and every connection parameter are how
 * the developer reached the database in the first place and a suite that guessed
 * them would fail for reasons unrelated to what it asserts.
 *
 * Author: John Grimes
 */

/** Which components of a connection URL to replace. */
export interface ConnectionUrlChanges {
  /** The role to connect as. */
  readonly user?: string;
  /** Its password. */
  readonly password?: string;
  /** The database to connect to, unqualified. */
  readonly database?: string;
}

/**
 * Replaces the named components of a connection URL and keeps the rest.
 *
 * Every replacement is percent-encoded. That is the failure `composeDatabaseUrl`
 * in `apps/server/src/config.ts` documents: a userinfo component that is not
 * encoded can terminate early and silently point the connection at a different
 * host, which for a suite whose whole subject is which identity connected would
 * be a false pass rather than a failure.
 *
 * @param url - The connection URL to derive from.
 * @param changes - The components to replace. An absent one is carried across.
 * @param variable - The environment variable `url` came from, named in the error
 *   rather than quoted: a connection URL contains a password.
 * @returns The derived URL.
 * @throws {Error} When `url` cannot be parsed.
 * @example
 * ```ts
 * const asProbe = databaseUrlWith(ownerUrl, {
 *   user: "signet_probe",
 *   password: "probe",
 * });
 * ```
 */
export function databaseUrlWith(
  url: string,
  changes: ConnectionUrlChanges,
  variable = "SIGNET_TEST_DATABASE_URL",
): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`${variable} is not a valid connection URL`);
  }

  if (changes.user !== undefined) {
    parsed.username = encodeURIComponent(changes.user);
  }
  if (changes.password !== undefined) {
    parsed.password = encodeURIComponent(changes.password);
  }
  if (changes.database !== undefined) {
    parsed.pathname = `/${encodeURIComponent(changes.database)}`;
  }

  return parsed.toString();
}
