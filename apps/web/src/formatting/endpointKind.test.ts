/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  audienceWording,
  capabilityLabelFor,
  defaultClientScopes,
  discoveryDocument,
  discoveryLabel,
  ENDPOINT_KIND_OPTIONS,
  endpointKindLabel,
  presetsFor,
  ruleDescriptionHint,
  visibleCapabilities,
} from "./endpointKind.js";

import type { PresetView } from "../api/types.js";

describe("endpointKindLabel", () => {
  it("names each kind as the console shows it", () => {
    expect(endpointKindLabel("smart")).toBe("SMART on FHIR");
    expect(endpointKindLabel("oauth")).toBe("OAuth / OpenID Connect");
  });
});

describe("ENDPOINT_KIND_OPTIONS", () => {
  it("offers both kinds, SMART first", () => {
    expect(ENDPOINT_KIND_OPTIONS.map((option) => option.value)).toEqual([
      "smart",
      "oauth",
    ]);
  });

  it("explains each kind", () => {
    for (const option of ENDPOINT_KIND_OPTIONS) {
      expect(option.description.length).toBeGreaterThan(20);
    }
  });
});

describe("audienceWording", () => {
  it("calls the audience a FHIR base URL on a SMART endpoint", () => {
    const wording = audienceWording("smart");
    expect(wording.label).toBe("FHIR base URL");
    expect(wording.placeholder).toBe("https://fhir.example.org/fhir");
    expect(wording.fronting("https://fhir.example.org/fhir")).toBe(
      "fronting https://fhir.example.org/fhir",
    );
  });

  it("calls it the audience on an OAuth endpoint", () => {
    const wording = audienceWording("oauth");
    expect(wording.label).toBe("Audience");
    expect(wording.hint).toContain("aud");
    expect(wording.hint).toContain("base URL");
    expect(wording.placeholder).toBe("https://api.example.org");
    // An OAuth endpoint does not front anything: it issues tokens for an API.
    expect(wording.fronting("https://api.example.org")).toBe(
      "issuing tokens for https://api.example.org",
    );
  });
});

describe("discoveryDocument", () => {
  it("is the SMART configuration on a SMART endpoint", () => {
    expect(
      discoveryDocument({
        kind: "smart",
        issuer: "https://signet.example.org/t/demo/e/fhir",
      }),
    ).toEqual({
      label: "SMART configuration",
      url: "https://signet.example.org/t/demo/e/fhir/.well-known/smart-configuration",
    });
  });

  it("is the OpenID configuration on an OAuth endpoint", () => {
    expect(
      discoveryDocument({
        kind: "oauth",
        issuer: "https://signet.example.org/t/demo/e/api",
      }),
    ).toEqual({
      label: "OpenID configuration",
      url: "https://signet.example.org/t/demo/e/api/.well-known/openid-configuration",
    });
  });
});

describe("discoveryLabel", () => {
  it("names each kind's discovery document", () => {
    expect(discoveryLabel("smart")).toBe("SMART configuration");
    expect(discoveryLabel("oauth")).toBe("OpenID configuration");
  });

  it("names it generically while the kind is unknown", () => {
    // The developer portal can show a request's status before, or without, learning
    // the endpoint's kind, and must not call an OpenID configuration a SMART one.
    expect(discoveryLabel(undefined)).toBe("Discovery document");
  });
});

describe("visibleCapabilities", () => {
  const capabilities = {
    supportsEhrLaunch: true,
    allowsPublicClients: false,
    supportsBackendServices: true,
    supportsV2Scopes: true,
    supportsOpenIdConnect: true,
  };

  it("shows every flag on a SMART endpoint, sorted by name", () => {
    expect(visibleCapabilities("smart", capabilities)).toEqual([
      "allowsPublicClients",
      "supportsBackendServices",
      "supportsEhrLaunch",
      "supportsOpenIdConnect",
      "supportsV2Scopes",
    ]);
  });

  it("hides the SMART-only flags on an OAuth endpoint", () => {
    // Offering them would only surface the API's refusal: an OAuth endpoint has no
    // launch, no SMART scope grammar and no patient banner.
    expect(visibleCapabilities("oauth", capabilities)).toEqual([
      "allowsPublicClients",
      "supportsBackendServices",
      "supportsOpenIdConnect",
    ]);
  });
});

describe("capabilityLabelFor", () => {
  it("calls Backend Services by its SMART name on a SMART endpoint", () => {
    expect(capabilityLabelFor("supportsBackendServices", "smart")).toBe(
      "Backend services",
    );
  });

  it("calls it client credentials on an OAuth endpoint", () => {
    expect(capabilityLabelFor("supportsBackendServices", "oauth")).toBe(
      "Client credentials",
    );
  });

  it("derives every other label the same way on both kinds", () => {
    expect(capabilityLabelFor("allowsPublicClients", "oauth")).toBe(
      "Public clients",
    );
    expect(capabilityLabelFor("allowsPublicClients", "smart")).toBe(
      "Public clients",
    );
  });
});

describe("defaultClientScopes", () => {
  it("starts a SMART client on the launch and patient scopes", () => {
    expect(defaultClientScopes("smart")).toEqual([
      "openid",
      "fhirUser",
      "launch",
      "launch/patient",
      "patient/*.rs",
    ]);
  });

  it("starts an OAuth client on the OpenID Connect identity scopes", () => {
    expect(defaultClientScopes("oauth")).toEqual([
      "openid",
      "profile",
      "email",
    ]);
  });
});

describe("presetsFor", () => {
  const preset = (id: string, kind: "smart" | "oauth"): PresetView => ({
    id,
    kind,
    name: id,
    description: "",
    policy: {},
    references: [],
  });
  const presets = [
    preset("smart-baseline", "smart"),
    preset("oauth-baseline", "oauth"),
    preset("pathling", "smart"),
  ];

  it("offers only SMART presets to a SMART endpoint", () => {
    expect(presetsFor("smart", presets).map((entry) => entry.id)).toEqual([
      "smart-baseline",
      "pathling",
    ]);
  });

  it("offers only OAuth presets to an OAuth endpoint", () => {
    expect(presetsFor("oauth", presets).map((entry) => entry.id)).toEqual([
      "oauth-baseline",
    ]);
  });
});

describe("ruleDescriptionHint", () => {
  it("warns that an OAuth grant rule's description is shown at consent", () => {
    // The consent screen phrases an API scope with the description of the rule
    // that granted it, so an internal note there reaches every end user.
    expect(ruleDescriptionHint("oauth", "scopeGrants")).toMatch(
      /^Shown to end users on the consent screen/u,
    );
  });

  it("keeps the reasoning hint wherever the description is not shown", () => {
    for (const [kind, list] of [
      ["smart", "scopeGrants"],
      ["oauth", "claimRules"],
      ["smart", "contextRules"],
    ] as const) {
      expect(ruleDescriptionHint(kind, list)).toBe(
        "Why this rule exists. The code view has no comments, so this is where the reasoning lives.",
      );
    }
  });
});
