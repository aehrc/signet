/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

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
 *
 * Author: John Grimes
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

/**
 * Waits for the stub app to finish, and returns the token response it received.
 *
 * The wait and the parse belong together: reading the panel before the exchange
 * has finished returns the previous render, and a test that did so would assert
 * against an empty object and pass for the wrong reason.
 *
 * @param page - The page the launch is running in.
 * @returns The parsed token response.
 */
export async function completedTokenResponse(
  page: Page,
): Promise<Record<string, unknown>> {
  await expect(page.getByTestId("status")).toHaveText("Launch complete.", {
    timeout: 20_000,
  });
  return JSON.parse(
    (await page.getByTestId("token-response").textContent()) ?? "{}",
  ) as Record<string, unknown>;
}

/**
 * Signs in, picks the patient, consents, and returns what the app came back with.
 *
 * The four steps between opening the app and having a token, which every
 * standalone launch in this suite performs identically. Separated from
 * {@link startLaunch} because what differs between those launches is the address
 * the app is opened at - which client, which scopes - and nothing after it.
 *
 * The picker cannot be skipped on this endpoint: `patient/*.rs` requires a patient
 * and a standalone launch names none, so the request cannot be consented to until
 * one is chosen. Consent is asked every time, because the seeded endpoint's consent
 * mode says so.
 *
 * @param page - The page the launch was started in.
 * @param patient - The patient to choose at the picker.
 * @returns The parsed token response.
 * @example
 * ```ts
 * await startLaunch(page);
 * const tokenResponse = await completeStandaloneLaunch(page, "pat-9");
 * ```
 */
export async function completeStandaloneLaunch(
  page: Page,
  patient: string,
): Promise<Record<string, unknown>> {
  await signIn(page);
  await choosePatient(page, patient);
  await decideConsent(page, "Allow");
  return await completedTokenResponse(page);
}

/**
 * The decoded access token claims the stub app is displaying.
 *
 * @param page - The page the launch ran in.
 * @returns The parsed claims.
 */
export async function accessTokenClaims(
  page: Page,
): Promise<Record<string, unknown>> {
  return JSON.parse(
    (await page.getByTestId("access-token-claims").textContent()) ?? "{}",
  ) as Record<string, unknown>;
}
