/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * One tenant account, signing in at two endpoints with one password.
 *
 * An end user belongs to the tenant, not to an endpoint, and signs in only at the
 * endpoints it has been explicitly given access to. This drives both halves of that
 * through the console and the end user's own sign-in pages: the account is refused
 * at an endpoint until it is given access there, and once it has access to both the
 * seeded SMART endpoint and the seeded OAuth endpoint, the same username and
 * password sign it in at each.
 *
 * The sign-ins are on each endpoint's management page, which has its own rate-limit
 * allowance, so this file spends nothing from the interactive sign-in budget that
 * `playwright.config.ts` documents. They run in a browser context of their own, with
 * no console session, as the account's holder would.
 *
 * Author: John Grimes
 */

import { expect, test } from "@playwright/test";

import {
  CONSOLE_STORAGE_STATE,
  ISSUER,
  NOTES_ISSUER,
} from "../support/stack.js";
import {
  addUser,
  giveAccess,
  NOTES_NAME,
  PATHLING_NAME,
  signInToManage,
  uniqueUser,
  USERS,
} from "../support/users.js";

test.describe("a tenant account", () => {
  test.use({ storageState: CONSOLE_STORAGE_STATE });

  test("signs in at every endpoint it has access to with one password", async ({
    page,
    browser,
  }) => {
    const user = uniqueUser("two-endpoints");
    const signedIn = `Signed in as ${user.displayName}.`;

    // ---- One account, given access to one endpoint ----------------------------
    await addUser(page, user);
    await giveAccess(page, PATHLING_NAME);

    const holder = await browser.newContext();
    try {
      const holderPage = await holder.newPage();

      // ---- Refused where it has no access: deny by default ---------------------
      await signInToManage(holderPage, NOTES_ISSUER, user);
      await expect(holderPage.getByRole("alert")).toBeVisible();
      await expect(holderPage.getByText(signedIn)).toHaveCount(0);

      // ---- Given access to the second endpoint ---------------------------------
      await giveAccess(page, NOTES_NAME);
      // The list names both endpoints the account can now sign in at.
      await page.goto(USERS);
      const row = page.getByRole("row").filter({ hasText: user.username });
      await expect(row.getByText(PATHLING_NAME, { exact: true })).toBeVisible();
      await expect(row.getByText(NOTES_NAME, { exact: true })).toBeVisible();

      // ---- The same password at both -------------------------------------------
      await signInToManage(holderPage, ISSUER, user);
      await expect(holderPage.getByText(signedIn)).toBeVisible();

      await signInToManage(holderPage, NOTES_ISSUER, user);
      await expect(holderPage.getByText(signedIn)).toBeVisible();
    } finally {
      await holder.close();
    }
  });
});
