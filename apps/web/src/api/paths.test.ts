/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  auditPath,
  clientPath,
  endpointPath,
  endUserPath,
  passkeyPath,
  PASSKEYS_PATH,
  PASSKEY_OPTIONS_PATH,
  PASSKEY_SIGN_IN_OPTIONS_PATH,
  PASSKEY_SIGN_IN_PATH,
  tenantPath,
} from "./paths.js";

describe("tenantPath", () => {
  it("builds a tenant path", () => {
    expect(tenantPath("demo")).toBe("/api/v1/tenants/demo");
  });

  it("appends a suffix", () => {
    expect(tenantPath("demo", "/members")).toBe("/api/v1/tenants/demo/members");
  });

  it("encodes the slug", () => {
    expect(tenantPath("a b/c")).toBe("/api/v1/tenants/a%20b%2Fc");
  });
});

describe("the passkey paths", () => {
  it("hangs the account's passkeys off the account rather than a tenant", () => {
    // A passkey belongs to the person, so no tenant slug appears anywhere in
    // these; putting one in would imply a passkey could be scoped to one.
    expect(PASSKEYS_PATH).toBe("/api/v1/account/passkeys");
    expect(PASSKEY_OPTIONS_PATH).toBe("/api/v1/account/passkeys/options");
  });

  it("addresses one passkey by identifier", () => {
    expect(passkeyPath("11111111-2222-3333-4444-555555555555")).toBe(
      "/api/v1/account/passkeys/11111111-2222-3333-4444-555555555555",
    );
  });

  it("encodes the identifier", () => {
    // Identifiers come back from the API and are uuids in practice, but the rule
    // here is that paths are built in one place with no exceptions to remember.
    expect(passkeyPath("a b/c")).toBe("/api/v1/account/passkeys/a%20b%2Fc");
  });

  it("puts the sign-in ceremony under the session resource", () => {
    // Both are unauthenticated, and both are named literally in the server's
    // allowlist - so the two spellings have to agree exactly.
    expect(PASSKEY_SIGN_IN_OPTIONS_PATH).toBe(
      "/api/v1/session/passkey-options",
    );
    expect(PASSKEY_SIGN_IN_PATH).toBe("/api/v1/session/passkey");
  });
});

describe("endpointPath", () => {
  it("nests under the tenant", () => {
    expect(endpointPath("demo", "fhir", "/keys")).toBe(
      "/api/v1/tenants/demo/endpoints/fhir/keys",
    );
  });
});

describe("clientPath", () => {
  it("encodes a client identifier", () => {
    // Client identifiers are not slugs: they may legitimately contain characters
    // that would otherwise change which resource is addressed.
    expect(clientPath("demo", "fhir", "app/one", "/secret")).toBe(
      "/api/v1/tenants/demo/endpoints/fhir/clients/app%2Fone/secret",
    );
  });
});

describe("endUserPath", () => {
  it("addresses a user by identifier", () => {
    expect(endUserPath("demo", "fhir", "abc", "/password")).toBe(
      "/api/v1/tenants/demo/endpoints/fhir/users/abc/password",
    );
  });
});

describe("auditPath", () => {
  it("omits the query string entirely when there is no filter", () => {
    expect(auditPath("demo")).toBe("/api/v1/tenants/demo/audit");
  });

  it("includes the filters that were set", () => {
    const path = auditPath("demo", { endpointSlug: "fhir", limit: 25 });
    expect(path).toContain("endpointSlug=fhir");
    expect(path).toContain("limit=25");
  });

  it("repeats the action parameter rather than joining it", () => {
    const path = auditPath("demo", {
      action: ["token.issued", "token.denied"],
    });
    expect(path).toContain("action=token.issued");
    expect(path).toContain("action=token.denied");
  });

  it("omits an empty value rather than filtering for the empty string", () => {
    const path = auditPath("demo", { actorType: "", action: [""] });
    expect(path).toBe("/api/v1/tenants/demo/audit");
  });

  it("carries an opaque cursor through unchanged", () => {
    const cursor = "eyJhdCI6IjIwMjYtMDgtMDQiLCJpZCI6ImEifQ";
    expect(auditPath("demo", { cursor })).toContain(`cursor=${cursor}`);
  });
});
