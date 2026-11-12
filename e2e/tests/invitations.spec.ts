/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Inviting an end user, from the console through to their first sign-in.
 *
 * The journey crosses two people and two browsers: an administrator who adds the
 * account and is shown the link once, and the invitee who opens it somewhere with
 * no console session, chooses a password and signs in with it. The link is read
 * from the dialog's text rather than the clipboard, which a headless browser does
 * not reliably grant.
 *
 * The sign-in at the end is on the management page, which has its own rate-limit
 * allowance, so this file spends nothing from the interactive sign-in budget that
 * `playwright.config.ts` documents.
 *
 * Author: John Grimes
 */

import { expect, test } from "@playwright/test";

import { CONSOLE_STORAGE_STATE, ISSUER, SIGNET } from "../support/stack.js";

/** The endpoint's Users tab, where the administrator's half starts. */
const USERS = `${SIGNET}/console/t/demo/e/pathling/users`;

test.describe("an invited end user", () => {
  test.use({ storageState: CONSOLE_STORAGE_STATE });

  test("chooses a password from the link and signs in with it", async ({
    page,
    browser,
  }) => {
    // Unique per run, for the reason `console.spec.ts` gives in `uniqueUser`.
    const suffix = `${String(Date.now())}-${String(Math.floor(Math.random() * 1e6))}`;
    const username = `invited-${suffix}`;
    const displayName = `Invited ${suffix}`;
    const password = `invited-${suffix}-password`;

    // ---- The administrator adds the account and is shown the link -----------
    await page.goto(USERS);
    await page.getByRole("button", { name: "Add user" }).click();
    await page.getByLabel("Username").fill(username);
    await page.getByLabel("Display name").fill(displayName);
    await page.getByLabel("Account setup").selectOption("invite");
    // An invited account is created without a password, so none is asked for.
    await expect(page.getByLabel("Password", { exact: true })).toHaveCount(0);
    await page.getByRole("button", { name: "Add", exact: true }).click();

    const dialog = page.getByRole("dialog", {
      name: `Invitation for ${username}`,
    });
    await expect(dialog).toBeVisible();
    const url = (await dialog.locator("code").textContent()) ?? "";
    expect(url).toMatch(
      new RegExp(`^${escapeRegExp(`${ISSUER}/invitation#`)}[A-Za-z0-9_-]+$`),
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
    await expect(page.getByRole("link", { name: displayName })).toBeVisible();

    // ---- The invitee opens the link in a browser of their own ---------------
    const invitee = await browser.newContext();
    try {
      const inviteePage = await invitee.newPage();
      await inviteePage.goto(url);
      await expect(
        inviteePage.getByRole("heading", { name: "Choose your password" }),
      ).toBeVisible();
      // The username is what they will sign in with, and the link is the only
      // place they are told it.
      await expect(
        inviteePage.getByText(username, { exact: true }),
      ).toBeVisible();

      await inviteePage.getByLabel("Password", { exact: true }).fill(password);
      await inviteePage
        .getByLabel("Confirm password", { exact: true })
        .fill(password);
      await inviteePage.getByRole("button", { name: "Set password" }).click();

      await expect(
        inviteePage.getByRole("heading", { name: "Password set" }),
      ).toBeVisible();

      // ---- And signs in with what they chose ----------------------------------
      await inviteePage.getByRole("link", { name: "Sign in" }).click();
      await expect(inviteePage).toHaveURL(`${ISSUER}/manage`);
      await inviteePage.getByLabel("Username").fill(username);
      await inviteePage.getByLabel("Password").fill(password);
      await inviteePage.getByRole("button", { name: "Sign in" }).click();
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
      await page.getByRole("link", { name: displayName }).click();
      await page.getByRole("button", { name: "Invite by email" }).click();
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
