import { describe, expect, it } from "vitest";

import {
  auditPath,
  clientPath,
  endpointPath,
  endUserPath,
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
