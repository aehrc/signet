import { describe, expect, it } from "vitest";

import {
  activeEndpointTab,
  clientRoute,
  endpointRoute,
  tenantRoute,
} from "./routes.js";

describe("tenantRoute", () => {
  it("builds a tenant route", () => {
    expect(tenantRoute("demo")).toBe("/console/t/demo");
  });

  it("appends a suffix", () => {
    expect(tenantRoute("demo", "/audit")).toBe("/console/t/demo/audit");
  });

  it("encodes the slug", () => {
    expect(tenantRoute("a/b")).toBe("/console/t/a%2Fb");
  });
});

describe("endpointRoute", () => {
  it("nests under the tenant", () => {
    expect(endpointRoute("demo", "fhir", "/keys")).toBe(
      "/console/t/demo/e/fhir/keys",
    );
  });
});

describe("clientRoute", () => {
  it("encodes a client identifier", () => {
    expect(clientRoute("demo", "fhir", "app one")).toBe(
      "/console/t/demo/e/fhir/clients/app%20one",
    );
  });
});

describe("activeEndpointTab", () => {
  it("is the overview for the endpoint's own path", () => {
    expect(activeEndpointTab("demo", "fhir", "/console/t/demo/e/fhir")).toBe(
      "",
    );
  });

  it("matches a tab", () => {
    expect(
      activeEndpointTab("demo", "fhir", "/console/t/demo/e/fhir/keys"),
    ).toBe("/keys");
  });

  it("keeps a nested page on its parent tab", () => {
    // A client's detail page must not deselect the Clients tab.
    expect(
      activeEndpointTab("demo", "fhir", "/console/t/demo/e/fhir/clients/app-1"),
    ).toBe("/clients");
  });

  it("falls back to the overview for a path outside the endpoint", () => {
    expect(activeEndpointTab("demo", "fhir", "/console/t/demo/audit")).toBe("");
  });
});
