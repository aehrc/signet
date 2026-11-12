/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  federationFormValues,
  federationRequestBody,
} from "./federationEdit.js";

import type { IdpConfigView } from "../api/types.js";

/** A stored provider, with the fields a case cares about overridden. */
function configView(overrides: Partial<IdpConfigView> = {}): IdpConfigView {
  return {
    issuer: "https://sso.example.org",
    displayName: null,
    clientId: "signet",
    hasClientSecret: true,
    scopes: ["openid", "profile"],
    claimMappings: {},
    discoveryCachedAt: null,
    updatedAt: "2026-08-03T14:02:11.000Z",
    redirectUri: "https://signet.example.org/t/demo/e/api/federation/callback",
    ...overrides,
  };
}

describe("federationFormValues", () => {
  it("asks for openid and profile by default on a SMART endpoint", () => {
    expect(federationFormValues(null, "smart").scopes).toBe("openid profile");
  });

  it("asks for email too by default on an OAuth endpoint", () => {
    // An OAuth endpoint releases `email`, so it needs the upstream claim to map.
    expect(federationFormValues(null, "oauth").scopes).toBe(
      "openid profile email",
    );
  });

  it("reads the stored mappings, including email", () => {
    const values = federationFormValues(
      configView({
        claimMappings: { email: "mail", roles: "groups", displayName: "name" },
      }),
      "oauth",
    );

    expect(values.email).toBe("mail");
    expect(values.roles).toBe("groups");
    expect(values.displayNameClaim).toBe("name");
  });

  it("never shows a stored secret", () => {
    expect(federationFormValues(configView(), "smart").clientSecret).toBe("");
  });
});

describe("federationRequestBody", () => {
  const form = {
    ...federationFormValues(configView(), "smart"),
    fhirUser: "fhirUser",
    email: "mail",
    roles: "groups",
  };

  it("maps the FHIR user claim, not email, on a SMART endpoint", () => {
    expect(federationRequestBody(form, "smart")["claimMappings"]).toEqual({
      fhirUser: "fhirUser",
      roles: "groups",
    });
  });

  it("maps the email claim, not the FHIR user claim, on an OAuth endpoint", () => {
    // The API refuses a fhirUser mapping on an OAuth endpoint.
    expect(federationRequestBody(form, "oauth")["claimMappings"]).toEqual({
      email: "mail",
      roles: "groups",
    });
  });

  it("omits a blank secret, which keeps the stored one", () => {
    expect(federationRequestBody(form, "smart")).not.toHaveProperty(
      "clientSecret",
    );
  });

  it("sends a blank display name as null", () => {
    expect(federationRequestBody(form, "smart")["displayName"]).toBeNull();
  });

  it("splits the scopes on whitespace", () => {
    expect(
      federationRequestBody({ ...form, scopes: " openid  email " }, "oauth")[
        "scopes"
      ],
    ).toEqual(["openid", "email"]);
  });

  it("sends attribute claims one per line", () => {
    expect(
      federationRequestBody(
        { ...form, attributes: "department\nnpi" },
        "smart",
      )["claimMappings"],
    ).toMatchObject({ attributes: ["department", "npi"] });
  });
});
