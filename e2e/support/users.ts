/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The console's Users page and a user's Endpoint access section, as functions.
 *
 * An end user belongs to the tenant and signs in only at the endpoints it has been
 * given access to, so most journeys that need an account need two steps: adding it
 * on the tenant's Users page, and giving it access on its detail page. Three suites
 * do both - `console.spec.ts`, `invitations.spec.ts` and `tenantUsers.spec.ts` - so
 * the steps live here once, which also keeps the duplication gate at zero.
 *
 * Author: John Grimes
 */

import { expect } from "@playwright/test";

import { SIGNET } from "./stack.js";

import type { Locator, Page } from "@playwright/test";

/** The seeded tenant's Users page, where every user journey starts. */
export const USERS = `${SIGNET}/console/t/demo/users`;

/** The seeded SMART endpoint's name, as the Endpoint access section shows it. */
export const PATHLING_NAME = "Pathling";

/** The seeded OAuth endpoint's name, as the Endpoint access section shows it. */
export const NOTES_NAME = "Notes";

/** An account one test owns for the duration of the test. */
export interface TestUser {
  readonly username: string;
  readonly displayName: string;
  readonly password: string;
}

/**
 * Names an account no other test and no earlier run has used.
 *
 * The display name carries the suffix as well as the username, and that is not
 * belt-and-braces: tests find their user by the name in the table, the suite is
 * expected to run against a stack it did not create, and two runs against one
 * long-lived stack would otherwise leave two rows with the same name and every
 * lookup after the first would be ambiguous. The random half is for workers that
 * start inside the same millisecond.
 *
 * @param prefix - What this account is for, so a leftover row explains itself.
 */
export function uniqueUser(prefix: string): TestUser {
  const suffix = `${String(Date.now())}-${String(Math.floor(Math.random() * 1e6))}`;
  return {
    username: `${prefix}-${suffix}`,
    displayName: `${prefix} ${suffix}`,
    password: `${prefix}-${suffix}-password`,
  };
}

/** How the Add user form sets the account up. */
export type AccountSetup = "password" | "persona" | "invite";

/**
 * Adds an account through the console's own Add user form.
 *
 * Returns on the new account's detail page, which is where the form sends the
 * administrator: the account has access to no endpoint yet, and that page is where
 * it is given some.
 *
 * Each test makes its own rather than editing a seeded account: the seeded
 * clinician and persona are what `launch.spec.ts` and `grants.spec.ts` sign in and
 * pick with, and a test that renamed or disabled one of them would break those from
 * a long way away.
 *
 * @param page - A console page, signed in as an administrator.
 * @param user - The account to create, from {@link uniqueUser}.
 * @param setup - A password now, a persona, or an invitation later.
 */
export async function addUser(
  page: Page,
  user: TestUser,
  setup: AccountSetup = "password",
): Promise<void> {
  await page.goto(USERS);
  await page.getByRole("button", { name: "Add user" }).click();
  if (setup === "persona") {
    await page.getByLabel("This is a persona").check();
  }
  await page.getByLabel("Username").fill(user.username);
  await page.getByLabel("Display name").fill(user.displayName);
  if (setup === "invite") {
    await page.getByLabel("Account setup").selectOption("invite");
    // An invited account is created without a password, so none is asked for.
    await expect(page.getByLabel("Password", { exact: true })).toHaveCount(0);
  }
  if (setup === "password") {
    await page.getByLabel("Password", { exact: true }).fill(user.password);
  }
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: user.displayName, exact: true }),
  ).toBeVisible();
}

/**
 * One endpoint's row in a user's Endpoint access section.
 *
 * @param page - A user's detail page.
 * @param endpointName - The endpoint's display name.
 */
export function accessRow(page: Page, endpointName: string): Locator {
  return page.getByRole("region", { name: `Access to ${endpointName}` });
}

/**
 * Gives the account on the current detail page access to an endpoint.
 *
 * Returns once the page has reported the access as given, so a caller can sign in
 * at the endpoint straight away.
 *
 * @param page - A user's detail page, signed in as an administrator.
 * @param endpointName - The endpoint's display name.
 */
export async function giveAccess(
  page: Page,
  endpointName: string,
): Promise<void> {
  const row = accessRow(page, endpointName);
  await row.getByRole("button", { name: "Give access" }).click();
  await expect(row.getByText(`Access given to ${endpointName}.`)).toBeVisible();
  await expect(
    row.getByRole("button", { name: "Withdraw access" }),
  ).toBeVisible();
}

/**
 * Signs in on an endpoint's management page, the end user's own sign-in surface.
 *
 * The management page rather than a launch: it has its own session and its own
 * rate-limit allowance, so signing in here spends nothing from the interactive
 * sign-in budget `playwright.config.ts` documents. The caller asserts what the page
 * answered, since a refusal is as much a result as a success.
 *
 * @param page - A page in a browser context with no end-user session there.
 * @param issuer - The endpoint's issuer identifier, which is its URL prefix.
 * @param user - The account to sign in as.
 */
export async function signInToManage(
  page: Page,
  issuer: string,
  user: Pick<TestUser, "username" | "password">,
): Promise<void> {
  await page.goto(`${issuer}/manage`);
  await page.getByLabel("Username").fill(user.username);
  await page.getByLabel("Password").fill(user.password);
  await page.getByRole("button", { name: "Sign in" }).click();
}
