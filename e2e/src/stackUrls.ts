/**
 * Where the compose stack is, worked out from the environment.
 *
 * One module rather than a lookup per caller, because the three places that need
 * these URLs - the Playwright configuration, the global setup and the specs' own
 * `support/stack.ts` - have to agree. They did not: all three honoured
 * `SIGNET_PORT` and none honoured `PATHLING_PORT` or `APP_PORT`, so moving the
 * stack meant setting five variables rather than three.
 *
 * **These variables have to be exported into the shell.** Bun loads a `.env` file
 * into its own process and does not pass the values to the processes it spawns, so
 * a `SIGNET_PORT` in `.env.local` reaches neither `docker compose` nor Playwright.
 * See the root `.env.example`.
 *
 * Author: John Grimes
 */

/** The three URLs the suite addresses the stack by. */
export interface StackUrls {
  /** Signet's origin. */
  signet: string;
  /** Pathling's FHIR base URL, which is the audience tokens are minted for. */
  fhir: string;
  /** The stub SMART app's origin. */
  app: string;
}

/**
 * Reads a variable, treating an empty value as absent.
 *
 * An exported-but-cleared variable arrives as an empty string, and reading that as
 * a port would produce `http://localhost:/fhir` - a URL that fails much later than
 * the mistake.
 *
 * @param env - the environment to read.
 * @param name - the variable to read.
 * @returns the value, or `undefined` if it is unset or empty.
 */
function setting(
  env: Record<string, string | undefined>,
  name: string,
): string | undefined {
  const value = env[name];
  return value === undefined || value === "" ? undefined : value;
}

/**
 * Works out where the stack is from the environment.
 *
 * Each service takes its port from a variable, defaulting to the port the compose
 * file publishes. A base URL, where one is set, wins outright rather than being
 * combined with the port: a stack somewhere other than `localhost` - a remote
 * host, another scheme, a path prefix - is not expressible as a port.
 *
 * @param env - the environment to read, normally `process.env`.
 * @returns the URLs of the three services the suite drives.
 * @example
 * ```ts
 * resolveStackUrls({ PATHLING_PORT: "8180" }).fhir;
 * // => "http://localhost:8180/fhir"
 * ```
 */
export function resolveStackUrls(
  env: Record<string, string | undefined>,
): StackUrls {
  const signetPort = setting(env, "SIGNET_PORT") ?? "3000";
  const pathlingPort = setting(env, "PATHLING_PORT") ?? "8080";
  const appPort = setting(env, "APP_PORT") ?? "4000";
  return {
    signet: setting(env, "SIGNET_BASE_URL") ?? `http://localhost:${signetPort}`,
    fhir:
      setting(env, "PATHLING_BASE_URL") ??
      `http://localhost:${pathlingPort}/fhir`,
    app: setting(env, "APP_BASE_URL") ?? `http://localhost:${appPort}`,
  };
}
