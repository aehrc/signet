/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { endpointCreateSchema, endpointPatchSchema } from "./endpoints.js";

describe("the endpoint login message", () => {
  it("accepts a message of up to 1000 characters", () => {
    expect(
      endpointPatchSchema.safeParse({ loginMessage: "x".repeat(1000) }).success,
    ).toBe(true);
  });

  it("refuses a message longer than 1000 characters", () => {
    expect(
      endpointPatchSchema.safeParse({ loginMessage: "x".repeat(1001) }).success,
    ).toBe(false);
  });

  it("accepts null, which removes the message", () => {
    expect(endpointPatchSchema.parse({ loginMessage: null })).toEqual({
      loginMessage: null,
    });
  });

  it("stores a message of only whitespace as no message", () => {
    // Otherwise the sign-in page would show an empty box.
    expect(endpointPatchSchema.parse({ loginMessage: " \n " })).toEqual({
      loginMessage: null,
    });
  });

  it("trims the whitespace around a message", () => {
    expect(
      endpointPatchSchema.parse({ loginMessage: "  Contact us.\n" }),
    ).toEqual({ loginMessage: "Contact us." });
  });

  it("may be set when an endpoint is created", () => {
    const parsed = endpointCreateSchema.parse({
      slug: "pathling",
      kind: "smart",
      name: "Pathling",
      audience: "https://fhir.example.org/fhir",
      loginMessage: "Contact us at pathling@csiro.au if you want an account.",
    });
    expect(parsed.loginMessage).toBe(
      "Contact us at pathling@csiro.au if you want an account.",
    );
  });
});
