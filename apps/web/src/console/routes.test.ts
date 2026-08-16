/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  activeEndpointTab,
  clientRoute,
  ENDPOINT_TABS,
  endpointRoute,
  endUserRoute,
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

describe("endUserRoute", () => {
  it("nests the user under the endpoint's users", () => {
    expect(endUserRoute("demo", "fhir", "user-1")).toBe(
      "/console/t/demo/e/fhir/users/user-1",
    );
  });

  it("encodes every segment", () => {
    // A user id is a uuid in practice, but the tenant and endpoint slugs reach here
    // from the URL, so nothing is trusted to be safe.
    expect(endUserRoute("a/b", "c d", "u/1")).toBe(
      "/console/t/a%2Fb/e/c%20d/users/u%2F1",
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

  it("keeps a user's detail page on the Users tab", () => {
    expect(
      activeEndpointTab("demo", "fhir", "/console/t/demo/e/fhir/users/user-1"),
    ).toBe("/users");
  });

  it("falls back to the overview for a path outside the endpoint", () => {
    expect(activeEndpointTab("demo", "fhir", "/console/t/demo/audit")).toBe("");
  });
});

describe("ENDPOINT_TABS", () => {
  it("gives every tab an icon", () => {
    // The tab bar renders each tab's octicon beside its label, so a tab added
    // without one would render nothing where the icon belongs.
    for (const tab of ENDPOINT_TABS) {
      expect(tab.icon).toBeDefined();
    }
  });
});
