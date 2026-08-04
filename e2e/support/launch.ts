/**
 * The steps of a launch, as functions.
 *
 * The specs read as a sequence of what a person does rather than as a sequence of
 * selectors, and - the reason this file exists rather than the steps being inline
 * - a change to a control's label is one edit instead of one per test.
 *
 * Each helper waits for the page it acts on before acting. Without that, a test
 * that raced ahead would fill a field on the page it was leaving and fail
 * somewhere else entirely.
 */

import { expect } from "@playwright/test";

import { APP, FHIR, ISSUER, SEED } from "./stack.js";

import type { Page } from "@playwright/test";

/** Opens the stub app, which begins a standalone launch. */
export async function startLaunch(page: Page): Promise<void> {
  await page.goto(
    `${APP}/?iss=${encodeURIComponent(ISSUER)}&aud=${encodeURIComponent(FHIR)}`,
  );
}

/** Signs in on Signet's own page, as the seeded clinician unless told otherwise. */
export async function signIn(
  page: Page,
  credentials: { readonly username: string; readonly password: string } = SEED,
): Promise<void> {
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await page.getByLabel("Username").fill(credentials.username);
  await page.getByLabel("Password").fill(credentials.password);
  await page.getByRole("button", { name: "Sign in" }).click();
}

/** Chooses the patient the authorization is about. */
export async function choosePatient(
  page: Page,
  patient: string,
): Promise<void> {
  await expect(
    page.getByRole("heading", { name: "Choose a record" }),
  ).toBeVisible();
  await page.getByLabel("Patient identifier").fill(patient);
  await page.getByRole("button", { name: "Continue" }).click();
}

/** Approves or declines at the consent screen. */
export async function decideConsent(
  page: Page,
  decision: "Allow" | "Deny",
): Promise<void> {
  await expect(
    page.getByRole("heading", { name: "Allow access?" }),
  ).toBeVisible();
  await page.getByRole("button", { name: decision, exact: true }).click();
}
