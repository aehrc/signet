/**
 * Author: John Grimes
 */

import { expect, test as setup } from "@playwright/test";

import {
  CONSOLE_STORAGE_STATE,
  SEED,
  SIGNET,
  VIEWER_STORAGE_STATE,
} from "../support/stack.js";

/**
 * Signs in to the console once and saves the session for the suite.
 *
 * Not merely a convenience. Signing in per test would have every worker
 * authenticating repeatedly from one address, which is exactly what the sign-in
 * rate limit refuses - so a suite written that way fails in a way that looks like
 * a broken console and is actually the product working. Doing it once here keeps
 * the suite under the limit and leaves the limit itself asserted where it belongs,
 * in `apps/server/src/http/rateLimit.integration.test.ts`.
 */
setup("authenticate as an operator", async ({ page }) => {
  await page.goto(`${SIGNET}/console`);
  await page.getByLabel("Email").fill(SEED.adminEmail);
  await page.getByLabel("Password").fill(SEED.adminPassword);
  await page.getByRole("button", { name: /sign in/i }).click();

  await expect(page.getByRole("link", { name: "pathling" })).toBeVisible();
  await page.context().storageState({ path: CONSOLE_STORAGE_STATE });
});

/**
 * The same, for the read-only identity.
 *
 * A viewer sees the console and can write nothing through it. Proving that needs a
 * session that holds the role, which no amount of asserting from the admin session
 * can substitute for.
 */
setup("authenticate as a viewer", async ({ page }) => {
  await page.goto(`${SIGNET}/console`);
  await page.getByLabel("Email").fill(SEED.viewerEmail);
  await page.getByLabel("Password").fill(SEED.viewerPassword);
  await page.getByRole("button", { name: /sign in/i }).click();

  await expect(page.getByRole("link", { name: "pathling" })).toBeVisible();
  await page.context().storageState({ path: VIEWER_STORAGE_STATE });
});
