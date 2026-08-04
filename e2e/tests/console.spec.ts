/**
 * Author: John Grimes
 */

import { expect, test } from "@playwright/test";

import { CONSOLE_STORAGE_STATE, SEED, SIGNET } from "../support/stack.js";

/**
 * The console, in a browser.
 *
 * Three things are worth driving through the real UI rather than the API beneath
 * it: that an operator can reach an endpoint at all, that the policy simulator
 * answers with a decoded token, and that what the launch suite did is visible in
 * the audit trail afterwards. Each of those spans pages, queries and navigations
 * that unit tests cannot.
 *
 * The session comes from `auth.setup.ts`, which signs in once for the whole
 * suite. The sign-in *refusal* gets its own block, with no stored session.
 */

test.describe("an authenticated operator", () => {
  test.use({ storageState: CONSOLE_STORAGE_STATE });

  test("opens the endpoint from the tenant's list", async ({ page }) => {
    await page.goto(`${SIGNET}/console`);
    await page.getByRole("link", { name: "pathling" }).click();

    // The overview shows the issuer, which is the value an operator copies into
    // their FHIR server's configuration.
    await expect(
      page.getByText(`${SIGNET}/t/demo/e/pathling`).first(),
    ).toBeVisible();
  });

  test("simulates a token without issuing one", async ({ page }) => {
    await page.goto(`${SIGNET}/console/t/demo/e/pathling/policy`);

    await page.getByLabel("Requested scopes").fill("patient/Observation.rs");
    await page.getByLabel("Patient in context").fill("pat-9");
    await page.getByRole("button", { name: /simulate/i }).click();

    // The Pathling translation, shown before anything is published: this is what
    // makes an undocumented resource server matchable by inspection.
    await expect(
      page.getByText("pathling:read:Observation").first(),
    ).toBeVisible({ timeout: 20_000 });
  });

  test("shows the launches the other suite performed", async ({ page }) => {
    await page.goto(`${SIGNET}/console/t/demo/audit`);

    // The trail is the record an operator answers questions from, so a launch
    // that happened and left nothing behind would be worse than one that failed.
    await expect(page.getByText("token.issued").first()).toBeVisible({
      timeout: 20_000,
    });
  });
});

test.describe("a caller with no session", () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test("is offered the sign-in page rather than the console", async ({
    page,
  }) => {
    await page.goto(`${SIGNET}/console/t/demo/e/pathling`);
    await expect(page.getByLabel("Email")).toBeVisible();
  });

  test("is refused a wrong password with the same message either way", async ({
    page,
  }) => {
    await page.goto(`${SIGNET}/console`);
    await page.getByLabel("Email").fill(SEED.adminEmail);
    await page.getByLabel("Password").fill("not the password");
    await page.getByRole("button", { name: /sign in/i }).click();

    const alert = page.getByRole("alert");
    await expect(alert).toBeVisible();
    const wrongPassword = (await alert.textContent()) ?? "";

    await page.getByLabel("Email").fill("nobody@example.org");
    await page.getByLabel("Password").fill("not the password");
    await page.getByRole("button", { name: /sign in/i }).click();
    // The same words for an address that exists and one that does not. The
    // console must not be a way to find out who has an account.
    await expect(page.getByRole("alert")).toHaveText(wrongPassword);
  });
});
