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

import type { Locator, Page } from "@playwright/test";

/** The endpoint's Users tab, where every user journey below starts. */
const USERS = `${SIGNET}/console/t/demo/e/pathling/users`;

/** The endpoint's Clients tab. */
const CLIENTS = `${SIGNET}/console/t/demo/e/pathling/clients`;

/** The endpoint's overview, which holds the settings and capability forms. */
const OVERVIEW = `${SIGNET}/console/t/demo/e/pathling`;

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

/** A client one of these tests owns for the duration of the test. */
interface TestClient {
  readonly clientId: string;
  readonly name: string;
}

/**
 * Names a client no other test and no earlier run has used.
 *
 * Same reasoning as {@link uniqueUser}: the seeded clients are what the launch and
 * grant suites authorize as, so a test that edited one would break those from a long
 * way away.
 *
 * @param prefix - What this client is for, so a leftover row explains itself.
 */
function uniqueClient(prefix: string): TestClient {
  const suffix = `${String(Date.now())}-${String(Math.floor(Math.random() * 1e6))}`;
  return { clientId: `${prefix}-${suffix}`, name: `${prefix} ${suffix}` };
}

/**
 * Registers a client through the console's own registration form.
 *
 * @param page - The browser page to drive.
 * @param client - The client to register, from {@link uniqueClient}.
 */
async function createClient(page: Page, client: TestClient): Promise<void> {
  await page.goto(CLIENTS);
  await page.getByRole("button", { name: "Register client" }).click();
  await page.getByLabel("Name").fill(client.name);
  await page.getByLabel("Client identifier").fill(client.clientId);
  await page.getByLabel("Redirect URIs").fill("https://app.test/callback");
  await page.getByRole("button", { name: "Register", exact: true }).click();
  await expect(page.getByRole("link", { name: client.name })).toBeVisible();
}

/** The panel with the given heading, and the form inside it. */
function panelForm(page: Page, heading: string): Locator {
  return page
    .locator("section")
    .filter({ has: page.getByRole("heading", { name: heading, exact: true }) })
    .locator("form");
}

/**
 * Proves a patch form sends nothing when nothing has changed.
 *
 * Three things, because each of them failed differently before there was anything
 * stopping them. Save is disabled and says why, so the operator is not left pressing
 * a button that does nothing. Editing enables it and undoing the edit disables it
 * again, so the state is about what the form holds rather than about the page having
 * been touched. And submitting the form directly - the button reached another way -
 * still sends no request, because the disabled button is a hint and the guard in
 * `PatchForm` is the rule.
 *
 * The assertion is an absent request rather than an absent visible effect: the admin
 * API accepts an empty patch and answers 200, writing an audit event that names no
 * field, so there is nothing on the page to assert against.
 *
 * @param page - The browser page to drive.
 * @param form - The form under test, from {@link panelForm}.
 * @param saveLabel - What that form's save button says.
 * @param edit - Makes a change to the form.
 * @param undo - Puts the form back the way it was.
 */
async function expectsNothingToSave(
  page: Page,
  form: Locator,
  saveLabel: string,
  edit: () => Promise<void>,
  undo: () => Promise<void>,
): Promise<void> {
  const patches: string[] = [];
  page.on("request", (request) => {
    if (request.method() === "PATCH") {
      patches.push(request.url());
    }
  });

  const save = form.getByRole("button", { name: saveLabel });
  await expect(save).toBeDisabled();
  await expect(form.getByText("Nothing has changed.")).toBeVisible();

  await edit();
  await expect(save).toBeEnabled();
  await undo();
  await expect(save).toBeDisabled();

  // `requestSubmit` fires the form's submit handler without going through the
  // button, which is the only way to reach the guard that matters: a disabled button
  // is a hint, and a page that trusted it would still post an empty patch to
  // anything that submitted the form another way.
  // Typed here rather than as `HTMLFormElement`: this package has no DOM library, so
  // the name would resolve to nothing and the call would be unchecked.
  await form.evaluate((element: { readonly requestSubmit: () => void }) => {
    element.requestSubmit();
  });
  // Long enough for a request to have left, given the assertions above have already
  // settled the form's state. There is no event to await: the point is the absence.
  await page.waitForTimeout(1000);

  expect(patches).toEqual([]);
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

    // FR-009.
    const name = page.getByLabel("Display name");
    await expectsNothingToSave(
      page,
      panelForm(page, "Edit"),
      "Save",
      async () => {
        await name.fill("Something Else");
      },
      async () => {
        await name.fill(user.displayName);
      },
    );
  });

  test("sends nothing when a client's Save is pressed with nothing changed", async ({
    page,
  }) => {
    // The client detail page had the same flaw the user detail page did: the patch
    // was built on submit and sent whatever it came to, including nothing.
    const client = uniqueClient("unchanged-client");
    await createClient(page, client);

    await page.getByRole("link", { name: client.name }).click();
    const form = panelForm(page, "Edit");
    await expect(form.getByLabel("Name")).toHaveValue(client.name);

    const name = form.getByLabel("Name");
    await expectsNothingToSave(
      page,
      form,
      "Save",
      async () => {
        await name.fill("Something Else");
      },
      async () => {
        await name.fill(client.name);
      },
    );

    // The positive control, on a client this test owns: a real edit still saves, so
    // the assertion above is about the empty patch and not about a form that cannot
    // save at all.
    await name.fill(`${client.name} renamed`);
    await form.getByRole("button", { name: "Save" }).click();
    await expect(page.getByText("Client saved.")).toBeVisible();
  });

  test("sends nothing when endpoint settings are saved unchanged", async ({
    page,
  }) => {
    // Read-only by construction: this test never saves, so it cannot disturb the
    // endpoint the launch and grant suites run against.
    await page.goto(OVERVIEW);
    const form = panelForm(page, "Settings");
    const name = form.getByLabel("Name");
    await expect(name).toHaveValue(/.+/);
    const loaded = (await name.inputValue()) ?? "";

    await expectsNothingToSave(
      page,
      form,
      "Save settings",
      async () => {
        await name.fill(`${loaded} edited`);
      },
      async () => {
        await name.fill(loaded);
      },
    );
  });

  test("sends nothing when endpoint capabilities are saved unchanged", async ({
    page,
  }) => {
    // Also read-only. A capability flag is a published conformance claim, so a test
    // that saved one would change what this endpoint advertises to every other suite.
    await page.goto(OVERVIEW);
    const form = panelForm(page, "Capabilities");
    const flag = form.getByLabel("POST to /authorize");
    await expect(flag).toBeVisible();
    const wasSet = await flag.isChecked();

    await expectsNothingToSave(
      page,
      form,
      "Save capabilities",
      async () => {
        await flag.setChecked(!wasSet);
      },
      async () => {
        await flag.setChecked(wasSet);
      },
    );
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
    await page.getByRole("button", { name: "Sign in", exact: true }).click();

    const alert = page.getByRole("alert");
    await expect(alert).toBeVisible();
    const wrongPassword = (await alert.textContent()) ?? "";

    await page.getByLabel("Email").fill("nobody@example.org");
    await page.getByLabel("Password").fill("not the password");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    // The same words for an address that exists and one that does not. The
    // console must not be a way to find out who has an account.
    await expect(page.getByRole("alert")).toHaveText(wrongPassword);
  });
});
