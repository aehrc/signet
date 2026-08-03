import { defineConfig, devices } from "@playwright/test";

/**
 * End-to-end suite. The stack under test (Signet, Pathling and a stub SMART
 * app) is brought up by docker-compose rather than by Playwright, because
 * Pathling needs a warm-up period that a `webServer` readiness check handles
 * poorly.
 *
 * Run `bun run stack:up` before this suite, or let CI do it.
 */
const baseURL = process.env["SIGNET_BASE_URL"] ?? "http://localhost:3000";

export default defineConfig({
  testDir: "./tests",
  fullyParallel: true,
  forbidOnly: !!process.env["CI"],
  retries: process.env["CI"] ? 2 : 0,
  workers: process.env["CI"] ? 2 : undefined,
  reporter: process.env["CI"]
    ? [["github"], ["html", { open: "never" }]]
    : [["html", { open: "never" }]],
  timeout: 60_000,
  expect: { timeout: 10_000 },
  use: {
    baseURL,
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
