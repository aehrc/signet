/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Inviting an end user, from the console through to their first sign-in.
 *
 * The journey crosses two people and two browsers: an administrator who adds the
 * account, gives it access to an endpoint and is shown the link once, and the
 * invitee who opens it somewhere with no console session, chooses a password and
 * signs in with it. The link is read from the dialog's text rather than the
 * clipboard, which a headless browser does not reliably grant.
 *
 * The link opens the tenant's invitation page rather than an endpoint's: the account
 * belongs to the tenant, and the password chosen there works at every endpoint it
 * has access to. An invitation is refused until the account has access to an
 * endpoint that signs in with a password, which the journey shows first.
 *
 * The sign-in at the end is on the management page, which has its own rate-limit
 * allowance, so this file spends nothing from the interactive sign-in budget that
 * `playwright.config.ts` documents.
 *
 * Author: John Grimes
 */

import { expect, test } from "@playwright/test";

import { CONSOLE_STORAGE_STATE, ISSUER, SIGNET } from "../support/stack.js";
import {
  addUser,
  giveAccess,
  PATHLING_NAME,
  signInToManage,
  uniqueUser,
} from "../support/users.js";

/** The tenant's invitation page, which every link opens. */
const INVITATION_PAGE = `${SIGNET}/t/demo/invitation`;

test.describe("an invited end user", () => {
  test.use({ storageState: CONSOLE_STORAGE_STATE });

  test("chooses a password from the link and signs in with it", async ({
    page,
    browser,
  }) => {
    const { username, displayName, password } = uniqueUser("invited");

    // ---- The administrator adds the account -----------------------------------
    await addUser(page, { username, displayName, password }, "invite");

    // With access to no endpoint, the password it chose would be checked nowhere,
    // so the invitation is refused - and the page says why before anyone presses.
    const invite = page.getByRole("button", { name: "Invite by email" });
    await expect(invite).toBeDisabled();
    await expect(
      page.getByText("None of the endpoints this account has access to"),
    ).toBeVisible();

    // ---- Gives it access, and is shown the link -------------------------------
    await giveAccess(page, PATHLING_NAME);
    await expect(invite).toBeEnabled();
    await invite.click();

    const dialog = page.getByRole("dialog", {
      name: `Invitation for ${username}`,
    });
    await expect(dialog).toBeVisible();
    const url = (await dialog.locator("code").textContent()) ?? "";
    expect(url).toMatch(
      new RegExp(`^${escapeRegExp(`${INVITATION_PAGE}#`)}[A-Za-z0-9_-]+$`),
    );

    // The mail client is handed the link, addressed to whoever was typed.
    await dialog.getByLabel("Email address").fill("invitee@example.org");
    const href =
      (await dialog
        .getByRole("link", { name: "Open in mail client" })
        .getAttribute("href")) ?? "";
    expect(href).toMatch(/^mailto:invitee@example\.org\?/);
    expect(decodeURIComponent(href)).toContain(url);

    await dialog.getByRole("button", { name: "Close" }).click();
    await expect(dialog).toHaveCount(0);

    // ---- The invitee opens the link in a browser of their own ---------------
    const invitee = await browser.newContext();
    try {
      const inviteePage = await invitee.newPage();
      await inviteePage.goto(url);
      await expect(
        inviteePage.getByRole("heading", { name: "Choose your password" }),
      ).toBeVisible();
      // The username is what they will sign in with, and the link is the only
      // place they are told it. The account is the tenant's, so the tenant is what
      // the page names.
      await expect(
        inviteePage.getByText(username, { exact: true }),
      ).toBeVisible();
      await expect(
        inviteePage.getByText("For your account with Demo Hospital."),
      ).toBeVisible();

      await inviteePage.getByLabel("Password", { exact: true }).fill(password);
      await inviteePage
        .getByLabel("Confirm password", { exact: true })
        .fill(password);
      await inviteePage.getByRole("button", { name: "Set password" }).click();

      await expect(
        inviteePage.getByRole("heading", { name: "Password set" }),
      ).toBeVisible();

      // ---- And signs in with what they chose, at the endpoint they can use ----
      // The tenant's page names no endpoint, so it sends them back to their app
      // rather than to one endpoint's sign-in page.
      await expect(
        inviteePage.getByRole("link", { name: "Sign in" }),
      ).toHaveCount(0);
      await signInToManage(inviteePage, ISSUER, { username, password });
      await expect(
        inviteePage.getByText(`Signed in as ${displayName}.`),
      ).toBeVisible();
      await expect(
        inviteePage.getByRole("button", { name: "Sign out" }),
      ).toBeVisible();

      // ---- The link was spent -------------------------------------------------
      await inviteePage.goto(url);
      await expect(
        inviteePage.getByRole("heading", { name: "This link does not work" }),
      ).toBeVisible();
      await expect(inviteePage.getByLabel("Password")).toHaveCount(0);

      // ---- A replacement link works in the tab that showed the spent one -----
      // Opening it there changes only the fragment, which does not reload the
      // page, so the page has to follow the fragment rather than its first value.
      // Reloaded first, so the panel shows that the spent link is no longer
      // outstanding rather than what it read before the invitee used it.
      await page.reload();
      await invite.click();
      const replacementDialog = page.getByRole("dialog", {
        name: `Invitation for ${username}`,
      });
      const replacement =
        (await replacementDialog.locator("code").textContent()) ?? "";
      expect(replacement).not.toBe(url);
      await inviteePage.goto(replacement);
      await expect(
        inviteePage.getByRole("heading", { name: "Choose your password" }),
      ).toBeVisible();
    } finally {
      await invitee.close();
    }
  });
});

/**
 * Escapes a literal for use inside a regular expression.
 *
 * @param value - The text to match exactly.
 */
function escapeRegExp(value: string): string {
  return value.replaceAll(/[.*+?^${}()|[\]\\/]/g, String.raw`\$&`);
}
