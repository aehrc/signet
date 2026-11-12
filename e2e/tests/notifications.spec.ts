/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * A registration request, filed in the portal, reaching the reviewers' inboxes.
 *
 * The whole path a reviewer depends on: a developer submits the portal form in a
 * browser, the shipped image sends through a real SMTP relay (Mailpit, in the
 * compose stack), and the link in the message opens the request in the console.
 * The integration suite covers who is told and what happens when the relay
 * fails; this is the proof that the artefact that ships sends anything at all.
 *
 * Author: John Grimes
 */

import { expect, test } from "@playwright/test";

import {
  CONSOLE_STORAGE_STATE,
  ISSUER,
  MAIL,
  SEED,
  SIGNET,
} from "../support/stack.js";

/** A message as Mailpit's search lists it. */
interface MailpitSummary {
  readonly ID: string;
  readonly Subject: string;
  readonly To: readonly { readonly Address: string }[];
}

// Signed in, so the console link in the message can be followed as the
// reviewer it was sent to. The portal itself takes no session.
test.use({ storageState: CONSOLE_STORAGE_STATE });

test("emails the reviewers a request filed in the portal, with a link that opens it", async ({
  page,
  request,
}) => {
  // Unique per run, so the search below finds this run's messages and not the
  // seed's or a previous run's.
  const appName = `Notification probe ${String(Date.now())}`;

  await page.goto(`${ISSUER}/apps`);
  await page.getByLabel("App name").fill(appName);
  await page.getByLabel("Contact email").fill("probe@example.org");
  await page.getByLabel("Redirect URIs").fill("https://probe.example.org/cb");
  await page.getByRole("button", { name: "Submit request" }).click();
  await expect(
    page.getByRole("status").getByText("Tracking token"),
  ).toBeVisible();

  // The notification is sent after the developer has been answered, so the
  // suite waits for it to land rather than expecting it already there.
  let messages: readonly MailpitSummary[] = [];
  await expect
    .poll(async () => {
      const response = await request.get(`${MAIL}/api/v1/search`, {
        params: { query: `"${appName}"` },
      });
      messages = ((await response.json()) as { messages: MailpitSummary[] })
        .messages;
      return messages.flatMap((message) => message.To.map((to) => to.Address));
    })
    .toContain(SEED.adminEmail);

  const recipients = messages.flatMap((message) =>
    message.To.map((to) => to.Address),
  );
  // The seed holds the viewer at `viewer`, which may not decide a request.
  expect(recipients).not.toContain(SEED.viewerEmail);
  // One message per reviewer, so nobody sees another's address.
  expect(messages.every((message) => message.To.length === 1)).toBe(true);

  const sent = messages.find((message) =>
    message.To.some((to) => to.Address === SEED.adminEmail),
  );
  expect(sent?.Subject).toBe(
    "New client registration request for Pathling (Demo Hospital)",
  );
  const body = (await (
    await request.get(`${MAIL}/api/v1/message/${String(sent?.ID)}`)
  ).json()) as { Text: string };
  expect(body.Text).toContain(`App name: ${appName}`);

  const link = `${SIGNET}/console/t/demo/e/pathling/requests`;
  expect(body.Text).toContain(link);

  // The link is the one thing in the message Signet vouches for, so follow it.
  await page.goto(link);
  await expect(page.getByText(appName).first()).toBeVisible();
});
