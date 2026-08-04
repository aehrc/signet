/**
 * Author: John Grimes
 */

import { defineConfig, devices } from "@playwright/test";

/**
 * The end-to-end suite.
 *
 * The stack under test - Signet, Pathling, Postgres and a stub SMART app - is
 * brought up by docker-compose rather than by Playwright. Pathling starts a Spark
 * session before it serves anything, which takes long enough that a `webServer`
 * readiness check is the wrong tool: it would either time out or mask a real
 * failure to start.
 *
 * Run `bun run stack:up` before this suite. The global setup runs the seed, which
 * is idempotent, so a suite against an already-running stack cannot fail for want
 * of a fixture.
 *
 * `SIGNET_PORT` moves the whole stack, issuer identifiers included, for a machine
 * where 3000 is taken. Set the same value here and in compose.
 *
 * **Running it twice inside a minute will fail, and that is the product working.**
 * End-user sign-ins are limited to ten a minute per address; one run of this suite
 * spends seven of them and the whole suite comes from one address. A second run
 * started before the window rolls over is refused with "Too many requests", which
 * surfaces as a sign-in page that will not proceed. Wait a minute between runs, or
 * run a single spec. The budget is written down in `tests/grants.spec.ts`; anything
 * added here that signs in interactively has to come out of it.
 */
const signetPort = process.env["SIGNET_PORT"] ?? "3000";
const baseURL =
  process.env["SIGNET_BASE_URL"] ?? `http://localhost:${signetPort}`;

export default defineConfig({
  testDir: "./tests",
  globalSetup: "./globalSetup.ts",
  fullyParallel: true,
  forbidOnly: !!process.env["CI"],
  retries: process.env["CI"] ? 2 : 0,
  workers: process.env["CI"] ? 2 : undefined,
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
    },
  ],
});
