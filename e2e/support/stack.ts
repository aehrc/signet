/**
 * Where the stack is, and what the seed put in it.
 *
 * One module rather than an environment lookup per spec, so that moving the stack
 * to another port is one variable and not a search-and-replace. The values match
 * `scripts/seedStack.mjs`; if they drift, the suite fails on its first assertion
 * rather than somewhere confusing.
 *
 * Author: John Grimes
 */

import { resolveStackUrls } from "../src/stackUrls.js";

const urls = resolveStackUrls(process.env);

/** Signet's origin. */
export const SIGNET = urls.signet;

/** The endpoint's issuer identifier, which is also its URL prefix. */
export const ISSUER = `${SIGNET}/t/demo/e/pathling`;

/** Pathling's FHIR base URL, which is the audience tokens are minted for. */
export const FHIR = urls.fhir;

/** The stub SMART app. */
export const APP = urls.app;

/**
 * Where the console's signed-in session is saved.
 *
 * One sign-in for the whole suite: see `tests/auth.setup.ts` for why repeating it
 * per test is not merely wasteful.
 */
export const CONSOLE_STORAGE_STATE = "playwright/.auth/console.json";

/**
 * Where the read-only console session is saved.
 *
 * A second session rather than a re-sign-in per test, for the same reason as the
 * first. It exists so that a role below admin can be shown to read everything and
 * be offered nothing - an assertion the admin session cannot make.
 */
export const VIEWER_STORAGE_STATE = "playwright/.auth/viewer.json";

/**
 * The accounts and clients the seed creates.
 *
 * The administrator's credentials are read from `SIGNET_E2E_*` rather than from
 * `SIGNET_BOOTSTRAP_*`, and the distinction is not cosmetic. `SIGNET_BOOTSTRAP_*`
 * configures the first account of *a developer's own* Signet instance, and
 * `.envrc` exports it into every shell in this repository. The compose stack
 * bootstraps itself with its own fixed values, so inheriting the developer's
 * would make the suite sign in with credentials the stack under test has never
 * heard of - which fails as a 401 from the seed, a long way from the cause.
 */
export const SEED = {
  username: "clinician",
  password: "clinician-password",
  adminEmail: process.env["SIGNET_E2E_ADMIN_EMAIL"] ?? "ops@example.org",
  adminPassword:
    process.env["SIGNET_E2E_ADMIN_PASSWORD"] ?? "correct horse battery staple",
  /** Holds `viewer` in the demo tenant, and may therefore write nothing. */
  viewerEmail: process.env["SIGNET_E2E_VIEWER_EMAIL"] ?? "viewer@example.org",
  viewerPassword:
    process.env["SIGNET_E2E_VIEWER_PASSWORD"] ??
    "read only horse battery staple",
  /**
   * The identity the passkey journey signs in and out as.
   *
   * Its own, because that journey signs out - which revokes the session the saved
   * storage states hold, and would break every console test running beside it.
   */
  passkeyEmail:
    process.env["SIGNET_E2E_PASSKEY_EMAIL"] ?? "passkeys@example.org",
  passkeyPassword:
    process.env["SIGNET_E2E_PASSKEY_PASSWORD"] ??
    "passkey horse battery staple",
  backendClientId: "stub-backend",
  backendSecret: "stub-backend-secret-value-0000",
  /** The public client the stub app launches as. */
  publicClientId: "stub-app",
  /** Holds a shared secret; the only client type granted `offline_access`. */
  confidentialClientId: "stub-confidential",
  confidentialSecret: "stub-confidential-secret-value-0000",
  /**
   * A second confidential client, used only by the refresh-reuse scenario.
   *
   * Reuse detection revokes every token the client holds, so that scenario would
   * pull the tokens out from under any test sharing a client with it.
   */
  reuseClientId: "stub-reuse",
  reuseSecret: "stub-reuse-secret-value-0000",
  /** Authenticates by signing an assertion rather than presenting a secret. */
  asymmetricClientId: "stub-asymmetric",
} as const;
