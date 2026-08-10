/**
 * The passkey journey, in a real browser against the real server.
 *
 * This is the proof the rest of the passkey work is measured against. The unit and
 * integration suites drive a software authenticator of our own making; what they
 * cannot show is that a *browser* will do any of this - that `navigator.credentials`
 * accepts the options the server generates, that the origin it reports matches the
 * one the server expects, that a discoverable credential comes back without an email
 * having been typed. Chromium's virtual authenticator, driven over CDP, is the only
 * way to assert that headlessly and deterministically.
 *
 * **One identity, and it is not shared.** The journey signs out, which revokes the
 * session `auth.setup.ts` saved for the other console suites. So it uses an identity
 * of its own - `bootstrap-passkey` in the compose stack creates it - and signs in
 * with a password once, which is the whole of its call on the administrator sign-in
 * allowance.
 *
 * **The authenticator is per-test.** A virtual authenticator lives on the CDP
 * session, and a credential created in one test would otherwise be offered in the
 * next; the tests run in one file and would stop being independent.
 *
 * Author: John Grimes
 */

import { expect, test } from "@playwright/test";

import { SEED, SIGNET } from "../support/stack.js";

import type { CDPSession, Page } from "@playwright/test";

/** No stored session: this file signs itself in. */
test.use({ storageState: { cookies: [], origins: [] } });

/**
 * Names a passkey no other test and no earlier run has used.
 *
 * The suite is expected to run against a stack it did not create, and this account
 * keeps whatever it registers - so two runs would otherwise leave two rows with the
 * same name and every lookup after the first would be ambiguous. Each test also
 * removes what it registered, so repeated runs cannot fill the account to its cap.
 */
function uniquePasskeyName(prefix: string): string {
  return `${prefix} ${String(Date.now())}-${String(Math.floor(Math.random() * 1e6))}`;
}

/**
 * Attaches a virtual authenticator to the page.
 *
 * Internal transport, user-verifying and resident-key capable, which is what a
 * platform authenticator with a fingerprint reader is - the configuration the server
 * demands in its options and the one a person would actually use.
 *
 * `automaticPresenceSimulation` makes the authenticator answer the prompt itself; a
 * headless browser has nobody to press the button.
 *
 * @param page - The page whose browser context should hold the authenticator.
 * @returns The CDP session, so the test can detach it afterwards.
 */
async function attachAuthenticator(page: Page): Promise<CDPSession> {
  const session = await page.context().newCDPSession(page);
  await session.send("WebAuthn.enable");
  await session.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return session;
}

/** Signs in with the password, which is how every one of these tests starts. */
async function signInWithPassword(page: Page): Promise<void> {
  await page.goto(`${SIGNET}/console`);
  await page.getByLabel("Email").fill(SEED.passkeyEmail);
  await page.getByLabel("Password").fill(SEED.passkeyPassword);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByRole("link", { name: "pathling" })).toBeVisible();
}

/** Opens the passkey dialog from the account menu in the header. */
async function openPasskeyDialog(page: Page): Promise<void> {
  await page
    .getByRole("button", { name: new RegExp(`Account menu`, "i") })
    .click();
  await page.getByRole("button", { name: "Passkeys", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Passkeys", exact: true }),
  ).toBeVisible();
}

/** Removes a passkey through the dialog, confirming the password. */
async function removePasskey(page: Page, name: string): Promise<void> {
  await page.getByRole("button", { name: `Remove ${name}` }).click();
  await page.getByLabel("Current password").fill(SEED.passkeyPassword);
  await page.getByRole("button", { name: "Remove passkey" }).click();
  await expect(page.getByText(`Removed "${name}"`)).toBeVisible();
}

/**
 * Closes the dialog, signs out, and waits for the sign-in page.
 *
 * Both journeys pass through this: the point of each is what happens when the
 * passkey is presented afterwards, and getting there is not what is under test.
 */
async function closeDialogAndSignOut(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Close" }).first().click();
  await page
    .getByRole("button", { name: new RegExp("Account menu", "i") })
    .click();
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByLabel("Email")).toBeVisible();
}

/** Registers a passkey through the dialog, and waits for it to be listed. */
async function registerPasskey(page: Page, name: string): Promise<void> {
  await page.getByRole("button", { name: "Register a passkey" }).click();
  await page.getByLabel("Current password").fill(SEED.passkeyPassword);
  await page.getByLabel("Passkey name").fill(name);
  await page.getByRole("button", { name: "Create passkey" }).click();
  await expect(page.getByText(`Registered "${name}".`)).toBeVisible();
}

test.describe("passkeys", () => {
  test("registers a passkey, signs out, and signs back in with it", async ({
    page,
  }) => {
    const name = uniquePasskeyName("E2E virtual key");
    const cdp = await attachAuthenticator(page);
    try {
      await signInWithPassword(page);
      await openPasskeyDialog(page);

      // Scenario 1, steps 3 and 4: register, and see it listed with its dates.
      await registerPasskey(page, name);
      const row = page.getByRole("row").filter({ hasText: name });
      await expect(row).toBeVisible();
      // Never used yet, which is what the list must say rather than leaving blank.
      await expect(row.getByText("never")).toBeVisible();
      await expect(page.getByText(/of 10 passkeys/)).toBeVisible();

      // Scenario 2, step 1: the same authenticator is excluded from a second
      // registration, so no duplicate can be created.
      await page.getByRole("button", { name: "Register a passkey" }).click();
      await page.getByLabel("Current password").fill(SEED.passkeyPassword);
      await page.getByRole("button", { name: "Create passkey" }).click();
      await expect(page.getByText(/already holds a passkey/i)).toBeVisible();
      await page.getByRole("button", { name: "Cancel" }).click();

      // Scenario 2, step 2: a wrong password is refused before any prompt.
      await page.getByRole("button", { name: "Register a passkey" }).click();
      await page.getByLabel("Current password").fill("not the password");
      await page.getByRole("button", { name: "Create passkey" }).click();
      await expect(
        page.getByText("That password was not accepted"),
      ).toBeVisible();
      await page.getByRole("button", { name: "Cancel" }).click();

      // Scenario 1, step 5: sign out, then in again with one gesture.
      await closeDialogAndSignOut(page);

      // Nothing is typed: no email, no password, no code. That is SC-001, and it
      // is why this assertion is made by clicking one button and nothing else.
      await page
        .getByRole("button", { name: "Sign in with a passkey" })
        .click();
      await expect(page.getByRole("link", { name: "pathling" })).toBeVisible();

      // Scenario 1, step 6: the session works, and the passkey's last use is set.
      await openPasskeyDialog(page);
      const used = page.getByRole("row").filter({ hasText: name });
      await expect(used).toBeVisible();
      await expect(used.getByText("never")).toHaveCount(0);

      // Left as it was found, so a second run against this stack starts clean.
      await removePasskey(page, name);
    } finally {
      await cdp.detach();
    }
  });

  test("removes a passkey, and it stops signing anybody in", async ({
    page,
  }) => {
    const name = uniquePasskeyName("Removable key");
    const cdp = await attachAuthenticator(page);
    try {
      await signInWithPassword(page);
      await openPasskeyDialog(page);
      await registerPasskey(page, name);

      // Scenario 2, step 3.
      await removePasskey(page, name);

      await closeDialogAndSignOut(page);

      // The credential is still on the authenticator; the account no longer knows
      // it. The refusal is the generic one, and the password form is still there.
      await page
        .getByRole("button", { name: "Sign in with a passkey" })
        .click();
      await expect(
        page.getByText("Those credentials were not accepted"),
      ).toBeVisible();
      await expect(page.getByLabel("Password")).toBeVisible();
    } finally {
      await cdp.detach();
    }
  });

  test("offers no passkey button to a browser without WebAuthn", async ({
    page,
  }) => {
    // The other direction of FR-001. Asserted by removing the API before the
    // bundle loads, which is what a browser that does not implement it looks
    // like; the password form must be entirely unaffected.
    await page.addInitScript(() => {
      Reflect.deleteProperty(globalThis.navigator, "credentials");
      Reflect.deleteProperty(globalThis, "PublicKeyCredential");
    });

    await page.goto(`${SIGNET}/console`);

    await expect(page.getByLabel("Email")).toBeVisible();
    await expect(page.getByLabel("Password")).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Sign in with a passkey" }),
    ).toHaveCount(0);
  });
});
