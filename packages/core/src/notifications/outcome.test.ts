/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { summariseNotification } from "./outcome.js";

describe("summariseNotification", () => {
  it("reports success only when every reviewer was reached", () => {
    expect(summariseNotification(3, [])).toEqual({ ok: true, recipients: 3 });
  });

  // Nobody being told is not success, however cleanly nothing was sent: the
  // request sits unseen until somebody happens to open the console.
  it("reports a request nobody could be told about as a failure", () => {
    expect(summariseNotification(0, [])).toEqual({
      ok: false,
      reason: "no-recipients",
      recipients: 0,
      delivered: 0,
      errors: [],
    });
  });

  it("counts a partial delivery as a failure, with what was delivered", () => {
    expect(summariseNotification(3, ["EENVELOPE"])).toEqual({
      ok: false,
      reason: "delivery-failed",
      recipients: 3,
      delivered: 2,
      errors: ["EENVELOPE"],
    });
  });

  it("lists each distinct error once, in a stable order", () => {
    expect(
      summariseNotification(4, ["ETIMEDOUT", "EENVELOPE", "ETIMEDOUT"]),
    ).toMatchObject({ errors: ["EENVELOPE", "ETIMEDOUT"] });
  });
});
