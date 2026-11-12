/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { passwordChoiceIssues } from "./passwordChoice.js";

describe("passwordChoiceIssues", () => {
  it("accepts a long enough password typed the same way twice", () => {
    expect(passwordChoiceIssues("correct horse", "correct horse")).toEqual({});
  });

  it("accepts exactly eight characters", () => {
    expect(passwordChoiceIssues("12345678", "12345678")).toEqual({});
  });

  it("refuses a password shorter than eight characters, under the password", () => {
    expect(passwordChoiceIssues("1234567", "1234567")).toEqual({
      password: "Use at least 8 characters.",
    });
  });

  it("refuses a confirmation that differs, under the confirmation", () => {
    expect(passwordChoiceIssues("correct horse", "correct hose")).toEqual({
      confirmation: "The two passwords are not the same.",
    });
  });

  it("reports both problems at once", () => {
    expect(passwordChoiceIssues("short", "shorter")).toEqual({
      password: "Use at least 8 characters.",
      confirmation: "The two passwords are not the same.",
    });
  });
});
