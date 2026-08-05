/**
 * Author: John Grimes
 */

import { expect, test } from "@playwright/test";

import { CONSOLE_STORAGE_STATE, SEED, SIGNET } from "../support/stack.js";

import type { Page } from "@playwright/test";

/** The endpoint's Users tab, where every user journey below starts. */
const USERS = `${SIGNET}/console/t/demo/e/pathling/users`;

/**
 * Creates a user through the console's own Add user form.
 *
 * Each test makes its own rather than editing a seeded account: the seeded
 * clinician and persona are what `launch.spec.ts` and `grants.spec.ts` sign in and
 * pick with, and a test that renamed or disabled one of them would break those from
 * a long way away.
 *
 * @param page - The browser page to drive.
 * @param user - The account to create.
 * @param user.username - The username, which must be unique on the endpoint.
 * @param user.displayName - The display name to create it with.
 * @param user.password - The password, for a local account.
 * @param user.isPersona - True to create a password-free persona instead.
 */
async function createUser(
  page: Page,
  user: {
    readonly username: string;
    readonly displayName: string;
    readonly password?: string;
    readonly isPersona?: boolean;
  },
): Promise<void> {
  await page.goto(USERS);
  await page.getByRole("button", { name: "Add user" }).click();
  if (user.isPersona === true) {
    await page.getByLabel("This is a persona").check();
  }
  await page.getByLabel("Username").fill(user.username);
  await page.getByLabel("Display name").fill(user.displayName);
  if (user.isPersona !== true) {
    await page.getByLabel("Password").fill(user.password ?? "");
  }
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await expect(
    page.getByRole("link", { name: user.displayName }),
  ).toBeVisible();
}

/** A username no other run of the suite will have used. */
function uniqueUsername(prefix: string): string {
  return `${prefix}-${String(Date.now())}`;
}

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

  test("edits a user from their detail page", async ({ page }) => {
    const username = uniqueUsername("edit-target");
    await createUser(page, {
      username,
      displayName: "Edit Target",
      password: "edit-target-password",
    });

    // The rows carry no action buttons any more: the name is a link, and the
    // actions live with the detail that explains them (FR-007).
    const row = page.getByRole("row").filter({ hasText: username });
    await expect(row.getByRole("button", { name: "Disable" })).toHaveCount(0);
    await expect(row.getByRole("button", { name: "Delete" })).toHaveCount(0);

    await page.getByRole("link", { name: "Edit Target" }).click();

    // The summary states what cannot be edited, and the form pre-fills what can.
    await expect(page.getByText(username).first()).toBeVisible();
    await expect(page.getByLabel("Display name")).toHaveValue("Edit Target");

    await page.getByLabel("Display name").fill("Edited Target");
    await page.getByLabel("fhirUser reference").fill("Practitioner/e2e-1");
    await page.getByLabel("Roles").fill("clinician\nresearcher");
    await page.getByRole("button", { name: "Save" }).click();

    // Every operation reports its outcome; silence would not be an answer.
    await expect(page.getByText("User saved.")).toBeVisible();

    await page.goto(USERS);
    await expect(
      page.getByRole("link", { name: "Edited Target" }),
    ).toBeVisible();
    // The username is what consents and the audit trail name them by, and no edit
    // may change it (FR-008).
    await expect(page.getByText(username).first()).toBeVisible();
  });

  test("clears a fhirUser reference rather than storing an empty one", async ({
    page,
  }) => {
    const username = uniqueUsername("clear-target");
    await createUser(page, {
      username,
      displayName: "Clear Target",
      password: "clear-target-password",
    });

    await page.getByRole("link", { name: "Clear Target" }).click();
    await page.getByLabel("fhirUser reference").fill("Practitioner/e2e-2");
    await page.getByRole("button", { name: "Save" }).click();
    await expect(page.getByText("User saved.")).toBeVisible();

    await page.getByLabel("fhirUser reference").fill("");
    await page.getByRole("button", { name: "Save" }).click();
    await expect(page.getByText("User saved.")).toBeVisible();

    // Reloaded rather than asserted against the form's own state: the point is what
    // the server stored, which is a cleared reference and not an empty string.
    await page.reload();
    await expect(page.getByLabel("fhirUser reference")).toHaveValue("");
    await page.goto(USERS);
    const row = page.getByRole("row").filter({ hasText: username });
    await expect(row.getByText("none").first()).toBeVisible();
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
