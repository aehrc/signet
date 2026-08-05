/**
 * Author: John Grimes
 */

import { expect, test } from "@playwright/test";

import { signIn, startLaunch } from "../support/launch.js";
import {
  CONSOLE_STORAGE_STATE,
  SEED,
  SIGNET,
  VIEWER_STORAGE_STATE,
} from "../support/stack.js";

import type { Page } from "@playwright/test";

/** The endpoint's Users tab, where every user journey below starts. */
const USERS = `${SIGNET}/console/t/demo/e/pathling/users`;

/** An account one of these tests owns for the duration of the test. */
interface TestUser {
  readonly username: string;
  readonly displayName: string;
  readonly password: string;
}

/**
 * Names an account no other test and no earlier run has used.
 *
 * The display name carries the suffix as well as the username, and that is not
 * belt-and-braces: these tests find their user by the name in the table, the suite
 * is expected to run against a stack it did not create, and two runs against one
 * long-lived stack would otherwise leave two rows called "Edit Target" and every
 * lookup after the first would be ambiguous. The random half is for workers that
 * start inside the same millisecond.
 *
 * @param prefix - What this account is for, so a leftover row explains itself.
 */
function uniqueUser(prefix: string): TestUser {
  const suffix = `${String(Date.now())}-${String(Math.floor(Math.random() * 1e6))}`;
  return {
    username: `${prefix}-${suffix}`,
    displayName: `${prefix} ${suffix}`,
    password: `${prefix}-password`,
  };
}

/**
 * Creates a user through the console's own Add user form.
 *
 * Each test makes its own rather than editing a seeded account: the seeded
 * clinician and persona are what `launch.spec.ts` and `grants.spec.ts` sign in and
 * pick with, and a test that renamed or disabled one of them would break those from
 * a long way away.
 *
 * @param page - The browser page to drive.
 * @param user - The account to create, from {@link uniqueUser}.
 * @param isPersona - True to create a password-free persona instead.
 */
async function createUser(
  page: Page,
  user: TestUser,
  isPersona = false,
): Promise<void> {
  await page.goto(USERS);
  await page.getByRole("button", { name: "Add user" }).click();
  if (isPersona) {
    await page.getByLabel("This is a persona").check();
  }
  await page.getByLabel("Username").fill(user.username);
  await page.getByLabel("Display name").fill(user.displayName);
  if (!isPersona) {
    await page.getByLabel("Password").fill(user.password);
  }
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await expect(
    page.getByRole("link", { name: user.displayName }),
  ).toBeVisible();
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
 *
 * The sign-in budget: end-user sign-ins are rate limited to ten a minute per
 * address, and the whole suite runs from one address inside a single window. This
 * file spends one of them - the launch that proves a console-set password is real,
 * which is the only way to prove it - alongside three in `grants.spec.ts` and four
 * in `launch.spec.ts`, leaving two for retries. The console sign-ins below are
 * administrator sign-ins, on a different limiter, and do not come out of it.
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
    const user = uniqueUser("edit-target");
    await createUser(page, user);
    const renamed = `${user.displayName} renamed`;

    // The rows carry no action buttons any more: the name is a link, and the
    // actions live with the detail that explains them (FR-007).
    const row = page.getByRole("row").filter({ hasText: user.username });
    await expect(row.getByRole("button", { name: "Disable" })).toHaveCount(0);
    await expect(row.getByRole("button", { name: "Delete" })).toHaveCount(0);

    await page.getByRole("link", { name: user.displayName }).click();

    // The summary states what cannot be edited, and the form pre-fills what can.
    await expect(page.getByText(user.username).first()).toBeVisible();
    await expect(page.getByLabel("Display name")).toHaveValue(user.displayName);

    await page.getByLabel("Display name").fill(renamed);
    await page.getByLabel("fhirUser reference").fill("Practitioner/e2e-1");
    await page.getByLabel("Roles").fill("clinician\nresearcher");
    await page.getByRole("button", { name: "Save" }).click();

    // Every operation reports its outcome; silence would not be an answer.
    await expect(page.getByText("User saved.")).toBeVisible();

    await page.goto(USERS);
    await expect(page.getByRole("link", { name: renamed })).toBeVisible();
    // The username is what consents and the audit trail name them by, and no edit
    // may change it (FR-008).
    await expect(page.getByText(user.username).first()).toBeVisible();
  });

  test("sends nothing when Save is pressed with nothing changed", async ({
    page,
  }) => {
    const user = uniqueUser("unchanged-target");
    await createUser(page, user);

    await page.getByRole("link", { name: user.displayName }).click();
    await expect(page.getByLabel("Display name")).toHaveValue(user.displayName);

    const patches: string[] = [];
    page.on("request", (request) => {
      if (request.method() === "PATCH") {
        patches.push(request.url());
      }
    });

    // FR-009. Asserted as an absent request rather than as an absent visible
    // effect: an empty patch is accepted by the API and writes an audit event
    // saying nothing changed, which the page cannot show and nobody can undo.
    await expect(page.getByRole("button", { name: "Save" })).toBeDisabled();
    await expect(page.getByText("Nothing has changed.")).toBeVisible();

    // Editing enables it and undoing the edit disables it again, so the state is
    // about what the form holds rather than about the page having loaded.
    await page.getByLabel("Display name").fill("Something Else");
    await expect(page.getByRole("button", { name: "Save" })).toBeEnabled();
    await page.getByLabel("Display name").fill(user.displayName);
    await expect(page.getByRole("button", { name: "Save" })).toBeDisabled();

    expect(patches).toEqual([]);
  });

  test("clears a fhirUser reference rather than storing an empty one", async ({
    page,
  }) => {
    const user = uniqueUser("clear-target");
    await createUser(page, user);

    await page.getByRole("link", { name: user.displayName }).click();
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
    const row = page.getByRole("row").filter({ hasText: user.username });
    await expect(row.getByText("none").first()).toBeVisible();
  });

  test("sets a password the user can then sign in with", async ({ page }) => {
    const user = uniqueUser("password-target");
    await createUser(page, user);

    await page.getByRole("link", { name: user.displayName }).click();
    await page.getByLabel("New password").fill("the-second-password");
    await page.getByRole("button", { name: "Set password" }).click();

    await expect(page.getByText("Password set.")).toBeVisible();
    // Cleared, so the value is not left sitting in the DOM of a page an operator
    // may walk away from.
    await expect(page.getByLabel("New password")).toHaveValue("");

    // The proof is a sign-in, not the confirmation message. Signet's sign-in page
    // only exists inside an authorization request, so this drives a real launch.
    // It spends one of the suite's end-user sign-ins; see the header's budget note.
    await startLaunch(page);
    await signIn(page, {
      username: user.username,
      password: "the-second-password",
    });

    // Reaching the next step of the launch is what says the credential was
    // accepted; a refusal would leave the page on its sign-in form.
    await expect(
      page.getByRole("heading", { name: "Choose a record" }),
    ).toBeVisible();
  });

  test("offers a persona no password form", async ({ page }) => {
    const user = uniqueUser("persona-target");
    await createUser(page, user, true);

    await page.getByRole("link", { name: user.displayName }).click();

    // A persona has no password by definition, so the console never offers the
    // operation the API would refuse.
    await expect(page.getByLabel("New password")).toHaveCount(0);
    await expect(page.getByText("Password", { exact: true })).toHaveCount(0);
    // Everything else is the same page.
    await expect(page.getByLabel("Display name")).toHaveValue(user.displayName);
  });

  test("disables and re-enables a user from their detail page", async ({
    page,
  }) => {
    const user = uniqueUser("state-target");
    await createUser(page, user);

    await page.getByRole("link", { name: user.displayName }).click();
    await expect(page.getByRole("button", { name: "Disable" })).toBeVisible();

    await page.getByRole("button", { name: "Disable" }).click();
    // The control flipping is the page's own report of the state it just changed;
    // the summary row is the same fact read back off the server's answer.
    await expect(page.getByRole("button", { name: "Enable" })).toBeVisible();
    await expect(page.getByText(/^Disabled /)).toBeVisible();

    await page.getByRole("button", { name: "Enable" }).click();
    await expect(page.getByRole("button", { name: "Disable" })).toBeVisible();
    await expect(page.getByText("Enabled", { exact: true })).toBeVisible();
  });

  test("deletes a user and returns to the users table", async ({ page }) => {
    const user = uniqueUser("delete-target");
    await createUser(page, user);

    await page.getByRole("link", { name: user.displayName }).click();

    // The confirmation has to say what is lost and what the alternative is, so it
    // is asserted rather than merely accepted.
    const confirmations: string[] = [];
    page.on("dialog", (dialog) => {
      confirmations.push(dialog.message());
      void dialog.accept();
    });

    await page.getByRole("button", { name: "Delete user" }).click();

    await expect(page).toHaveURL(USERS);
    await expect(
      page.getByRole("link", { name: user.displayName }),
    ).toHaveCount(0);
    expect(confirmations[0]).toContain("consents and tokens");
    expect(confirmations[0]).toContain("Disabling");
  });

  test("shows the launches the other suite performed", async ({ page }) => {
    // Filtered rather than read off the top of the trail. The first page holds the
    // most recent events, and the rest of this file writes enough of them - a user
    // created, edited, disabled and deleted per test - to push a launch that
    // happened seconds earlier off it. Filtering is also what an operator would do.
    //
    // Retried around a reload because the launches this asserts on are performed by
    // another spec file, on another worker: arriving first is a matter of timing,
    // and the query does not poll on its own.
    await expect(async () => {
      await page.goto(`${SIGNET}/console/t/demo/audit`);
      await page.getByLabel("Actions").fill("token.issued");

      // The trail is the record an operator answers questions from, so a launch
      // that happened and left nothing behind would be worse than one that failed.
      await expect(page.getByText("token.issued").first()).toBeVisible({
        timeout: 5000,
      });
    }).toPass({ timeout: 60_000 });
  });
});

test.describe("a viewer-role operator", () => {
  test.use({ storageState: VIEWER_STORAGE_STATE });

  test("reads a user's detail page and is offered no write", async ({
    page,
  }) => {
    // The seeded clinician, read-only: this block writes nothing, so using a
    // shared fixture cannot disturb the suites that launch as them.
    await page.goto(USERS);
    await page.getByRole("link", { name: "Dr Casey Clinician" }).click();

    // Everything is visible.
    await expect(page.getByLabel("Display name")).toHaveValue(
      "Dr Casey Clinician",
    );
    await expect(page.getByLabel("fhirUser reference")).toHaveValue(
      "Practitioner/clinician-1",
    );

    // And nothing is editable. Both directions of FR-010: the inputs are disabled,
    // and the controls that write are absent rather than present-and-failing.
    await expect(page.getByLabel("Display name")).toBeDisabled();
    await expect(page.getByLabel("fhirUser reference")).toBeDisabled();
    await expect(page.getByLabel("Roles")).toBeDisabled();
    await expect(page.getByLabel("Patients")).toBeDisabled();
    await expect(page.getByRole("button", { name: "Save" })).toHaveCount(0);
    await expect(page.getByLabel("New password")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Disable" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Delete user" })).toHaveCount(
      0,
    );
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
