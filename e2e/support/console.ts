/**
 * The console's own chrome, as functions.
 *
 * The header's account menu is the only way to the passkey dialog, and two suites
 * now need it: `tests/passkeys.spec.ts` drives the ceremonies through it, and
 * `tests/responsive.spec.ts` opens it to measure a dialog no route can reach. One
 * copy rather than two, so a change to the menu's labels is one edit - and so the
 * duplication gate, which is at zero, stays met.
 *
 * Author: John Grimes
 */

import { expect } from "@playwright/test";

import type { Page } from "@playwright/test";

/**
 * Opens the passkey dialog from the account menu in the header.
 *
 * Returns once the dialog's heading is on screen, so a caller can act on the
 * dialog without racing the menu's own animation.
 *
 * @param page - A console page, signed in as a person rather than as a token.
 * @throws {Error} When the menu, the entry or the dialog does not appear.
 * @example
 * ```ts
 * await page.goto(`${SIGNET}/console/t/demo`);
 * await openPasskeyDialog(page);
 * ```
 */
export async function openPasskeyDialog(page: Page): Promise<void> {
  await page
    .getByRole("button", { name: new RegExp("Account menu", "i") })
    .click();
  await page.getByRole("button", { name: "Passkeys", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Passkeys", exact: true }),
  ).toBeVisible();
}
