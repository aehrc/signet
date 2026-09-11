/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Resolution of runtime configuration from the environment.
 *
 * The Helm chart supplies the database either as a single URL (external
 * database) or as discrete parts with the password from the bundled PostgreSQL
 * subchart's own secret. Both shapes are supported here so the chart never has
 * to invent a password that the database does not actually have.
 *
 * Author: John Grimes
 */

/** A resolved, validated Signet configuration. */
export interface SignetConfig {
  readonly port: number;
  /** Public origin; endpoint issuers are derived from it. No trailing slash. */
  readonly publicUrl: string;
  readonly databaseUrl: string;
  /** Envelope key protecting endpoint signing keys at rest. */
  readonly masterKey: string;
  readonly logLevel: "debug" | "info" | "warn" | "error";
  /**
   * Directory holding the built UI, served for any path the API does not claim.
   *
   * Absent in development, where Vite serves the UI on its own port and proxies
   * `/api` here.
   */
  readonly webRoot: string | undefined;
  /**
   * Permits outbound fetches to private addresses and over plain HTTP.
   *
   * Signet fetches two user-supplied URLs - a client's `jwks_uri` and an upstream
   * IdP's issuer - and normally refuses any address that is not publicly
   * routable, because an authorization server is a valuable place to have an SSRF.
   * A development or connectathon stack legitimately needs the opposite: its
   * upstream IdP is `http://keycloak:8080` on a compose network.
   *
   * One flag rather than several, because it must be obvious in a manifest that
   * the guard is off. Never set it in production.
   */
  readonly allowPrivateOutboundFetches: boolean;
  /**
   * How many proxies stand between Signet and the caller, each appending to
   * `X-Forwarded-For`.
   *
   * The header is how the audit trail and the rate limiter learn an address, and
   * every entry a caller can write is one they choose. Only the entries appended
   * by the trusted proxies carry provenance, so the address is read from exactly
   * that far back - and when the chain is shorter than the count, or the count is
   * zero, the socket address is used instead. Default zero: a deployment that
   * says nothing gets the socket address, not whatever the caller wrote.
   */
  readonly trustedProxyCount: number;
}

/** Thrown when the environment cannot produce a usable configuration. */
export class ConfigError extends Error {
  /** @param message - An actionable description naming the offending variable. */
  public constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

/** The subset of `process.env` this module reads. */
export type Environment = Readonly<Record<string, string | undefined>>;

const LOG_LEVELS = new Set(["debug", "info", "warn", "error"]);

/** Reads a variable, treating blank strings as absent. */
function read(env: Environment, name: string): string | undefined {
  const value = env[name];
  if (value === undefined || value.trim().length === 0) {
    return undefined;
  }
  return value;
}

/**
 * Reads a boolean flag, accepting only the two spellings a manifest should use.
 *
 * Anything else throws rather than defaulting. A typo in
 * `SIGNET_ALLOW_PRIVATE_OUTBOUND_FETCHES` that silently read as `false` would be
 * harmless; one that silently read as `true` would turn off a security control,
 * and the failure mode of a misspelling should not depend on which of those it is.
 */
function readBoolean(env: Environment, name: string): boolean {
  const value = read(env, name);
  if (value === undefined) {
    return false;
  }
  if (value === "true" || value === "false") {
    return value === "true";
  }
  throw new ConfigError(`${name} must be "true" or "false", got "${value}"`);
}

/**
 * Builds a Postgres connection URL from discrete parts.
 *
 * The password is percent-encoded: generated passwords can contain characters
 * that would otherwise terminate the userinfo component and silently produce a
 * URL pointing somewhere else.
 */
function composeDatabaseUrl(env: Environment): string | undefined {
  const host = read(env, "SIGNET_DATABASE_HOST");
  if (host === undefined) {
    return undefined;
  }

  const name = read(env, "SIGNET_DATABASE_NAME");
  const user = read(env, "SIGNET_DATABASE_USER");
  if (name === undefined || user === undefined) {
    throw new ConfigError(
      "SIGNET_DATABASE_HOST is set, so SIGNET_DATABASE_NAME and SIGNET_DATABASE_USER are also required",
    );
  }

  const port = read(env, "SIGNET_DATABASE_PORT") ?? "5432";
  if (!/^\d+$/.test(port)) {
    throw new ConfigError(
      `SIGNET_DATABASE_PORT must be a number, got "${port}"`,
    );
  }

  const password = read(env, "SIGNET_DATABASE_PASSWORD");
  const credentials =
    password === undefined
      ? encodeURIComponent(user)
      : `${encodeURIComponent(user)}:${encodeURIComponent(password)}`;

  return `postgres://${credentials}@${host}:${port}/${encodeURIComponent(name)}`;
}

/** Strips any trailing slashes so issuer values concatenate predictably. */
function normalisePublicUrl(raw: string): string {
  const trimmed = raw.replace(/\/+$/, "");
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new ConfigError(`SIGNET_PUBLIC_URL is not a valid URL: "${raw}"`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new ConfigError(
      `SIGNET_PUBLIC_URL must be http or https, got "${parsed.protocol}"`,
    );
  }
  return trimmed;
}

/**
 * Resolves just the database URL.
 *
 * The `migrate` and `bootstrap` commands need a connection and nothing else, and
 * requiring the whole configuration for them would mean an operator supplying a public
 * URL and a master key to run a migration that uses neither - and being told off by name
 * when they did not.
 *
 * @param env - The environment to read.
 * @throws {ConfigError} When neither form of the connection setting is present, or both
 *   are.
 */
export function resolveDatabaseUrl(env: Environment): string {
  const explicitUrl = read(env, "SIGNET_DATABASE_URL");
  const composedUrl = composeDatabaseUrl(env);
  if (explicitUrl !== undefined && composedUrl !== undefined) {
    throw new ConfigError(
      "Set either SIGNET_DATABASE_URL or the SIGNET_DATABASE_* parts, not both",
    );
  }
  const databaseUrl = explicitUrl ?? composedUrl;
  if (databaseUrl === undefined) {
    throw new ConfigError(
      "SIGNET_DATABASE_URL or SIGNET_DATABASE_HOST is required",
    );
  }
  return databaseUrl;
}

/** The two identities the `migrate` command needs. */
export interface MigrationIdentities {
  /**
   * The connection the migrations are applied with.
   *
   * The owning identity: migrations are DDL, and the grants below are issued by
   * the role that owns the objects being granted.
   */
  readonly ownerUrl: string;
  /**
   * The role the grants are issued to, parsed out of the serving connection.
   *
   * A name, not a connection. `migrate` never uses the serving password, so the
   * migration job holds no credential it has no use for and rotating that
   * password is not a migration concern.
   */
  readonly servingRole: string;
}

/**
 * The username in a connection URL, decoded.
 *
 * @throws {ConfigError} When the URL cannot be parsed or carries no username,
 *   naming the variable it came from and quoting no part of it - a connection
 *   URL contains a password and these messages reach a Job's logs.
 */
function usernameOf(url: string, variable: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new ConfigError(`${variable} is not a valid connection URL`);
  }
  if (parsed.username.length === 0) {
    throw new ConfigError(
      `${variable} must name the role it connects as; it carries no username`,
    );
  }
  // Percent-decoded, because the grant has to name the role the database
  // actually has. Granting to `signet%20app` is a statement that succeeds and
  // leaves the real role with nothing.
  return decodeURIComponent(parsed.username);
}

/**
 * Resolves the two identities the `migrate` command acts with.
 *
 * `migrate` is the only command that needs more than one. It connects as the
 * owning identity, because migrations are DDL, and it grants the serving role
 * the access the server needs - so it has to know that role's name, which it
 * takes from the serving connection the server itself is configured with.
 *
 * Every refusal here is a deployment that could not enforce tenant isolation,
 * and the worst of them is the quiet one: two URLs naming the same role means
 * the server owns its tables, and Postgres exempts a table's owner from its
 * policies, so that deployment would serve while believing itself protected.
 * Signet is pre-release, so such a configuration is refused rather than
 * accommodated.
 *
 * @param env - The environment to read.
 * @returns The owner connection and the serving role's name.
 * @throws {ConfigError} When the owner URL is absent, either URL is unparseable
 *   or carries no username, or the two name the same role. Each message names
 *   the variable at fault and contains no part of a connection string.
 * @example
 * ```ts
 * const { ownerUrl, servingRole } = resolveMigrationIdentities(process.env);
 * await runMigrateCommand(ownerUrl, servingRole);
 * ```
 */
export function resolveMigrationIdentities(
  env: Environment,
): MigrationIdentities {
  // Resolved first, so that a deployment missing the connection every command
  // needs is told about that rather than about the one only `migrate` needs.
  const servingUrl = resolveDatabaseUrl(env);

  const ownerUrl = read(env, "SIGNET_DATABASE_OWNER_URL");
  if (ownerUrl === undefined) {
    throw new ConfigError(
      "SIGNET_DATABASE_OWNER_URL is required to migrate; it names the identity that owns the schema, which SIGNET_DATABASE_URL must not",
    );
  }

  const servingRole = usernameOf(servingUrl, "SIGNET_DATABASE_URL");
  const ownerRole = usernameOf(ownerUrl, "SIGNET_DATABASE_OWNER_URL");

  if (servingRole === ownerRole) {
    throw new ConfigError(
      `SIGNET_DATABASE_URL and SIGNET_DATABASE_OWNER_URL both name the role "${servingRole}". The serving role must be non-owning: Postgres exempts a table's owner from that table's policies, so a server connecting as the owner is not constrained by them.`,
    );
  }

  return { ownerUrl, servingRole };
}

/** What the `sweep` command acts with. */
export interface SweepConfiguration {
  /**
   * The connection the sweep is made on.
   *
   * The owning identity, for the reason `migrate` needs it: the sweep acts across
   * tenants, which is exactly what the serving role must not be able to do. Run as
   * the serving role every statement matches nothing, so the command checks the
   * role it was actually given rather than trusting the variable's name.
   */
  readonly ownerUrl: string;
  /**
   * How far behind the present the access token sweep's cut-off sits.
   *
   * Access token records are a revocation list rather than runtime state, and one
   * deleted the moment it expires turns a slightly late introspection - a resource
   * server whose clock is behind Signet's - into an unknown token rather than an
   * inactive one carrying its metadata.
   */
  readonly accessTokenGraceMs: number;
}

/** Milliseconds in each unit a duration may be written with. */
const DURATION_UNITS: Readonly<Record<string, number>> = {
  s: 1000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
};

/** The default access token grace period: a day. */
const DEFAULT_ACCESS_TOKEN_GRACE = "24h";

/**
 * The longest duration a variable may name: a century.
 *
 * Absurdly generous for a clock-skew allowance, and the point is the other end -
 * a value big enough to put the cut-off outside the range of a `Date` would
 * otherwise be discovered as a `RangeError` part-way through the sweep, after the
 * command had reported the identity it verified and deleted from three tables.
 */
const MAX_DURATION_MS = 100 * 365 * 86_400_000;

/**
 * Reads a duration written as a whole number and a unit, in milliseconds.
 *
 * The unit is mandatory. A bare `24` is ambiguous, and the reading that would
 * hurt - seconds, where an operator meant hours - is a sweep that deletes the
 * record of a token a resource server is about to introspect. A configuration
 * that cannot be read one way only is refused rather than guessed at.
 *
 * @throws {ConfigError} When the value is not a whole number followed by `s`,
 *   `m`, `h` or `d`.
 */
function readDuration(
  env: Environment,
  name: string,
  fallback: string,
): number {
  const value = read(env, name) ?? fallback;
  const match = /^(\d+)([smhd])$/.exec(value);
  const unit = match === null ? undefined : DURATION_UNITS[match[2] ?? ""];
  if (match === null || unit === undefined) {
    throw new ConfigError(
      `${name} must be a whole number followed by s, m, h or d - for example "24h" - got "${value}"`,
    );
  }

  const milliseconds = Number(match[1]) * unit;
  if (milliseconds > MAX_DURATION_MS) {
    throw new ConfigError(
      `${name} must be no more than 100 years, got "${value}"`,
    );
  }
  return milliseconds;
}

/**
 * Resolves what the `sweep` command acts with.
 *
 * Deliberately reads two variables and no others. The sweep needs a connection
 * that can act across tenants and a cut-off; it serves nothing, signs nothing and
 * has no issuer, so demanding a public URL or a master key would be an operator
 * being told off by name for omitting something the command never reads.
 *
 * It does not read `SIGNET_DATABASE_URL` either, and that is the difference from
 * {@link resolveMigrationIdentities}: `migrate` needs the serving role's *name* in
 * order to grant it, and the sweep grants nothing.
 *
 * @param env - The environment to read.
 * @returns The owner connection and the access token grace period.
 * @throws {ConfigError} When the owning identity is absent, or the grace period
 *   cannot be read. Neither message contains any part of a connection string.
 * @example
 * ```ts
 * await runSweepCommand(resolveSweepConfiguration(process.env));
 * ```
 */
export function resolveSweepConfiguration(
  env: Environment,
): SweepConfiguration {
  const ownerUrl = read(env, "SIGNET_DATABASE_OWNER_URL");
  if (ownerUrl === undefined) {
    throw new ConfigError(
      "SIGNET_DATABASE_OWNER_URL is required to sweep; the sweep acts across tenants, which the serving role cannot do - run as it, every statement matches nothing",
    );
  }

  return {
    ownerUrl,
    accessTokenGraceMs: readDuration(
      env,
      "SIGNET_SWEEP_ACCESS_TOKEN_GRACE",
      DEFAULT_ACCESS_TOKEN_GRACE,
    ),
  };
}

/**
 * Resolves configuration from an environment, throwing {@link ConfigError} with
 * an actionable message rather than starting up in a half-configured state.
 */
export function loadConfig(env: Environment): SignetConfig {
  const port = Number(read(env, "PORT") ?? "3000");
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new ConfigError(
      `PORT must be an integer between 1 and 65535, got "${env["PORT"]}"`,
    );
  }

  const publicUrlRaw = read(env, "SIGNET_PUBLIC_URL");
  if (publicUrlRaw === undefined) {
    throw new ConfigError(
      "SIGNET_PUBLIC_URL is required; endpoint issuers are derived from it",
    );
  }

  const databaseUrl = resolveDatabaseUrl(env);

  const masterKey = read(env, "SIGNET_MASTER_KEY");
  if (masterKey === undefined) {
    throw new ConfigError(
      "SIGNET_MASTER_KEY is required; it encrypts endpoint signing keys at rest",
    );
  }
  if (masterKey.length < 32) {
    throw new ConfigError("SIGNET_MASTER_KEY must be at least 32 characters");
  }

  const logLevel = read(env, "SIGNET_LOG_LEVEL") ?? "info";
  if (!LOG_LEVELS.has(logLevel)) {
    throw new ConfigError(
      `SIGNET_LOG_LEVEL must be one of debug, info, warn, error; got "${logLevel}"`,
    );
  }

  return {
    port,
    publicUrl: normalisePublicUrl(publicUrlRaw),
    databaseUrl,
    masterKey,
    logLevel: logLevel as SignetConfig["logLevel"],
    webRoot: read(env, "SIGNET_WEB_ROOT"),
    allowPrivateOutboundFetches: readBoolean(
      env,
      "SIGNET_ALLOW_PRIVATE_OUTBOUND_FETCHES",
    ),
    trustedProxyCount: readNonNegativeInteger(
      env,
      "SIGNET_TRUSTED_PROXY_COUNT",
    ),
  };
}

/**
 * Reads a non-negative integer, refusing anything else rather than defaulting.
 *
 * @param env - The environment to read.
 * @param name - The variable's name, for the error message.
 * @returns The value, or zero when the variable is absent.
 * @throws {ConfigError} When the variable is present but not a non-negative
 *   integer. A typo that silently read as zero would leave the limiter keying on
 *   the socket address of a proxy that forwards client-chosen addresses, which is
 *   the failure mode to avoid.
 */
function readNonNegativeInteger(env: Environment, name: string): number {
  const value = read(env, name);
  if (value === undefined) {
    return 0;
  }
  if (!/^\d+$/.test(value)) {
    throw new ConfigError(
      `${name} must be a non-negative integer, got "${value}"`,
    );
  }
  return Number(value);
}
