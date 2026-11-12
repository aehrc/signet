/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The OpenID Connect discovery document of an OAuth / OpenID Connect endpoint.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { buildOpenIdConfiguration } from "./build.js";
import {
  defaultEndpointCapabilities,
  OAUTH_DEFAULT_SCOPES_SUPPORTED,
} from "./capabilities.js";
import { SMART_ONLY_CAPABILITY_FLAGS } from "../endpointKind.js";

import type { EndpointCapabilityConfig } from "./types.js";

const ISSUER = "https://signet.example.com/t/acme/e/orders";
const API = "https://api.example.com/v1";

/** An OAuth endpoint as created, with every SMART-only flag off. */
function oauthConfig(
  overrides: Partial<EndpointCapabilityConfig> = {},
): EndpointCapabilityConfig {
  const smartOff = Object.fromEntries(
    SMART_ONLY_CAPABILITY_FLAGS.map((flag) => [flag, false]),
  );
  return defaultEndpointCapabilities(ISSUER, API, {
    ...smartOff,
    kind: "oauth",
    scopesSupported: OAUTH_DEFAULT_SCOPES_SUPPORTED,
    ...overrides,
  });
}

describe("buildOpenIdConfiguration - OAuth endpoint", () => {
  it("offers the authorization code grant with no SMART launch mode", () => {
    const document = buildOpenIdConfiguration(oauthConfig());
    expect(document.grant_types_supported).toEqual([
      "authorization_code",
      "client_credentials",
      "refresh_token",
    ]);
    expect(document.authorization_endpoint).toBe(`${ISSUER}/authorize`);
  });

  it("follows the client credentials and offline access flags", () => {
    const document = buildOpenIdConfiguration(
      oauthConfig({
        supportsBackendServices: false,
        supportsOfflineAccess: false,
      }),
    );
    expect(document.grant_types_supported).toEqual(["authorization_code"]);
  });

  it("advertises the OpenID Connect scopes and standard claims", () => {
    const document = buildOpenIdConfiguration(oauthConfig());
    expect(document.scopes_supported).toEqual([
      "openid",
      "profile",
      "email",
      "offline_access",
    ]);
    expect(document.claims_supported).toEqual([
      "sub",
      "iss",
      "aud",
      "exp",
      "iat",
      "name",
      "preferred_username",
      "email",
      "email_verified",
    ]);
  });

  it("keeps the SMART claims on a SMART endpoint", () => {
    const document = buildOpenIdConfiguration(
      defaultEndpointCapabilities(ISSUER, API),
    );
    expect(document.claims_supported).toContain("fhirUser");
    expect(document.claims_supported).not.toContain("email");
  });
});
