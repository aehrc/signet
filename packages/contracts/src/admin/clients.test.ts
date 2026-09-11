/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  clientCreateSchema,
  clientPatchSchema,
  clientRequestSchema,
} from "./clients.js";

/** A client registration that passes every other check. */
function baseCreate(): Record<string, unknown> {
  return {
    name: "Growth Chart",
    clientType: "public",
    redirectUris: ["https://app.example.org/callback"],
  };
}

describe("the client contracts", () => {
  it("registers a client whose URLs are all web URLs", () => {
    expect(
      clientCreateSchema.safeParse({
        ...baseCreate(),
        logoUrl: "https://app.example.org/logo.png",
        launchUri: "https://app.example.org/launch",
      }).success,
    ).toBe(true);
  });

  it("refuses a script-executing redirect URI at creation", () => {
    const result = clientCreateSchema.safeParse({
      ...baseCreate(),
      redirectUris: ["javascript:alert(document.cookie)"],
    });
    expect(result.success).toBe(false);
    expect(
      result.success ? [] : result.error.issues.map((issue) => issue.path[0]),
    ).toContain("redirectUris");
  });

  it("refuses a script-executing launch URI at creation", () => {
    expect(
      clientCreateSchema.safeParse({
        ...baseCreate(),
        launchUri: "javascript:alert(document.cookie)",
      }).success,
    ).toBe(false);
  });

  it("refuses a script-executing logo URL at creation", () => {
    expect(
      clientCreateSchema.safeParse({
        ...baseCreate(),
        logoUrl: "data:image/svg+xml,<svg onload=alert(1)>",
      }).success,
    ).toBe(false);
  });

  it("refuses a script-executing redirect URI on a patch", () => {
    expect(
      clientPatchSchema.safeParse({
        redirectUris: ["javascript:alert(document.cookie)"],
      }).success,
    ).toBe(false);
  });

  it("refuses a script-executing URL on a self-serve request", () => {
    for (const field of ["redirectUris", "logoUrl", "launchUri"]) {
      const value =
        field === "redirectUris"
          ? ["data:text/html,<script>alert(1)</script>"]
          : "javascript:alert(document.cookie)";
      expect(
        clientRequestSchema.safeParse({
          name: "Growth Chart",
          clientType: "public",
          requestedScopes: ["openid"],
          contactEmail: "dev@example.org",
          [field]: value,
        }).success,
      ).toBe(false);
    }
  });
});
