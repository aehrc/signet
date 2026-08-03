/**
 * Resolution of runtime configuration from the environment.
 *
 * The Helm chart supplies the database either as a single URL (external
 * database) or as discrete parts with the password from the bundled PostgreSQL
 * subchart's own secret. Both shapes are supported here so the chart never has
 * to invent a password that the database does not actually have.
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
  };
}
