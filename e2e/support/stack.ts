/**
 * Where the stack is, and what the seed put in it.
 *
 * One module rather than an environment lookup per spec, so that moving the stack
 * to another port is one variable and not a search-and-replace. The values match
 * `scripts/seedStack.mjs`; if they drift, the suite fails on its first assertion
 * rather than somewhere confusing.
 */

const SIGNET_PORT = process.env["SIGNET_PORT"] ?? "3000";

/** Signet's origin. */
export const SIGNET =
  process.env["SIGNET_BASE_URL"] ?? `http://localhost:${SIGNET_PORT}`;

/** The endpoint's issuer identifier, which is also its URL prefix. */
export const ISSUER = `${SIGNET}/t/demo/e/pathling`;

/** Pathling's FHIR base URL, which is the audience tokens are minted for. */
export const FHIR =
  process.env["PATHLING_BASE_URL"] ?? "http://localhost:8080/fhir";

/** The stub SMART app. */
export const APP = process.env["APP_BASE_URL"] ?? "http://localhost:4000";

/**
 * Where the console's signed-in session is saved.
 *
 * One sign-in for the whole suite: see `tests/auth.setup.ts` for why repeating it
 * per test is not merely wasteful.
 */
export const CONSOLE_STORAGE_STATE = "playwright/.auth/console.json";

/** The accounts and clients the seed creates. */
export const SEED = {
  username: "clinician",
  password: "clinician-password",
  adminEmail: process.env["SIGNET_BOOTSTRAP_EMAIL"] ?? "ops@example.org",
  adminPassword:
    process.env["SIGNET_BOOTSTRAP_PASSWORD"] ?? "correct horse battery staple",
  backendClientId: "stub-backend",
  backendSecret: "stub-backend-secret-value-0000",
} as const;
