/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { expect, test } from "@playwright/test";

// A deliberately thin suite for now: it proves the harness and the deployed
// stack are wired together. The real launch, grant and Pathling authority
// scenarios land in phase 7.

test("liveness probe responds", async ({ request }) => {
  const response = await request.get("/healthz");
  expect(response.ok()).toBe(true);
  expect(await response.json()).toEqual({ status: "ok" });
});

test("readiness probe responds", async ({ request }) => {
  const response = await request.get("/readyz");
  expect(response.ok()).toBe(true);
});
