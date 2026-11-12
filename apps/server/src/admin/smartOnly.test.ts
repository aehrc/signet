/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * What a client registration may not carry on an OAuth / OpenID Connect endpoint.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { oauthClientIssues } from "./smartOnly.js";

describe("oauthClientIssues", () => {
  it("refuses a launch URI, which only a SMART EHR launch uses", () => {
    expect(
      oauthClientIssues("oauth", { launchUri: "https://app.test/launch" }),
    ).toEqual([
      {
        path: "launchUri",
        message: "Not available on an OAuth / OpenID Connect endpoint",
      },
    ]);
  });

  it("allows clearing a launch URI", () => {
    expect(oauthClientIssues("oauth", { launchUri: null })).toEqual([]);
  });

  it("refuses an allowlist entry that is not an RFC 6749 scope-token", () => {
    const issues = oauthClientIssues("oauth", {
      allowedScopes: ["openid", 'bad scope"', "orders:read", String.raw`a\b`],
    });

    expect(issues.map((issue) => issue.path)).toEqual([
      "allowedScopes.1",
      "allowedScopes.3",
    ]);
    expect(issues[0]?.message).toMatch(/scope-token/u);
  });

  it("accepts any scope-token, SMART-shaped or not", () => {
    // On an OAuth endpoint a SMART-shaped string is just an opaque scope.
    expect(
      oauthClientIssues("oauth", {
        allowedScopes: ["openid", "email", "orders:read", "patient/*.rs"],
      }),
    ).toEqual([]);
  });

  it("finds nothing to refuse on a SMART endpoint", () => {
    expect(
      oauthClientIssues("smart", {
        launchUri: "https://app.test/launch",
        allowedScopes: ['bad scope"'],
      }),
    ).toEqual([]);
  });
});
