/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Whether an edit to an account's email address keeps its verified flag.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { withEmailVerification } from "./email.js";

const VERIFIED = { email: "jo@example.org", emailVerified: true };

describe("withEmailVerification", () => {
  it("unverifies a new address the edit did not vouch for", () => {
    expect(
      withEmailVerification(VERIFIED, { email: "jo@elsewhere.example" }),
    ).toEqual({ email: "jo@elsewhere.example", emailVerified: false });
  });

  it("unverifies a cleared address", () => {
    // Otherwise the flag outlives the address and attaches itself to the next one.
    expect(withEmailVerification(VERIFIED, { email: null })).toEqual({
      email: null,
      emailVerified: false,
    });
  });

  it("keeps the flag the edit names alongside a new address", () => {
    expect(
      withEmailVerification(VERIFIED, {
        email: "jo@elsewhere.example",
        emailVerified: true,
      }),
    ).toEqual({ email: "jo@elsewhere.example", emailVerified: true });
  });

  it("leaves an edit that does not change the address alone", () => {
    expect(
      withEmailVerification(VERIFIED, { email: "jo@example.org" }),
    ).toEqual({ email: "jo@example.org" });
    // Fields the rule does not read pass through untouched.
    const rename: { displayName: string; email?: string } = {
      displayName: "Jo",
    };
    expect(withEmailVerification(VERIFIED, rename)).toEqual({
      displayName: "Jo",
    });
  });

  it("can verify an address without changing it", () => {
    expect(
      withEmailVerification(
        { email: "jo@example.org", emailVerified: false },
        { emailVerified: true },
      ),
    ).toEqual({ emailVerified: true });
  });
});
