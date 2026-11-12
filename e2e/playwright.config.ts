/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { defineConfig, devices } from "@playwright/test";

import { resolveStackUrls } from "./src/stackUrls.js";

/**
 * The end-to-end suite.
 *
 * The stack under test - Signet, Pathling, Postgres, a stub SMART app and
 * oauth2-proxy in front of a regular app - is brought up by docker-compose rather
 * than by Playwright. Pathling starts a Spark
 * session before it serves anything, which takes long enough that a `webServer`
 * readiness check is the wrong tool: it would either time out or mask a real
 * failure to start.
 *
 * Run `bun run stack:up` before this suite. The global setup runs the seed, which
 * is idempotent, so a suite against an already-running stack cannot fail for want
 * of a fixture.
 *
 * `SIGNET_PORT`, `PATHLING_PORT`, `APP_PORT` and `PROXY_PORT` move the stack,
 * issuer identifiers included, for a machine where one of the default ports is taken. **Export them
 * into the shell**, so that this suite and `docker compose` read the same values:
 * Bun does not pass a variable it loaded from a `.env` file to the processes it
 * spawns, and neither `docker compose` nor Playwright is Bun.
 *
 * **Running it three times inside a minute will fail, and that is the product
 * working.** End-user sign-ins are limited per address, and the compose stack sets
 * the limit to thirty a minute with `SIGNET_SIGN_IN_RATE_LIMIT`. One run of this
 * suite spends eleven, and the whole suite comes from one address. A third run
 * started before the window rolls over is refused with "Too many requests", which
 * surfaces as a sign-in page that will not proceed. Wait a minute between runs, or
 * run a single spec. The budget is written down in `tests/grants.spec.ts`; anything
 * added here that signs in interactively adds to it.
 *
 * The administrator sign-ins are a separate allowance on the same limit, keyed by
 * route: two in `auth.setup.ts` and two in `tests/passkeys.spec.ts`, which signs in
 * with a password because its journey has to sign out again. The two passkey
 * sign-ins go to `POST /session/passkey`, which has an allowance of its own, so they
 * cost nothing here.
 */
const baseURL = resolveStackUrls(process.env).signet;

export default defineConfig({
  testDir: "./tests",
  globalSetup: "./globalSetup.ts",
  fullyParallel: true,
  forbidOnly: !!process.env["CI"],
  retries: process.env["CI"] ? 2 : 0,
  // Two on CI, and Playwright's own default locally. Spread rather than set to
  // `undefined`, which `exactOptionalPropertyTypes` refuses and which Playwright
  // would read as a configured value rather than an absent one.
  ...(process.env["CI"] ? { workers: 2 } : {}),
  reporter: process.env["CI"]
    ? [["github"], ["html", { open: "never" }]]
    : [["list"], ["html", { open: "never" }]],
  timeout: 60_000,
  expect: { timeout: 10_000 },
  use: {
    baseURL,
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  projects: [
    // Signs in once and saves the session. Everything else depends on it, so a
    // failure here fails the suite up front rather than as an unexplained
    // authentication error in every console test.
    { name: "setup", testMatch: /.*\.setup\.ts/ },
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
      dependencies: ["setup"],
      // The responsive spec belongs to `mobile` alone. Without this it would run
      // here too, at a desktop viewport, where its assertions say nothing.
      testIgnore: /responsive\.spec\.ts/,
    },
    {
      name: "mobile",
      use: {
        ...devices["Pixel 7"],
        // Narrower than the stock profile's 412px: 360 is the width the feature
        // is specified against, and the one an assertion has to hold at.
        viewport: { width: 360, height: 780 },
      },
      dependencies: ["setup"],
      // One spec, not the whole suite at a second viewport. Re-running every
      // journey on a phone would spend sign-ins the rate limit does not have,
      // and would prove the same authorization behaviour twice.
      testMatch: /responsive\.spec\.ts/,
    },
  ],
});
