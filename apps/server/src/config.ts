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
  };
}
