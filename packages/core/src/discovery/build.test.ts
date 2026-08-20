/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { buildOpenIdConfiguration, buildSmartConfiguration } from "./build.js";
import { defaultEndpointCapabilities } from "./capabilities.js";
import { endpointUrls } from "./endpoints.js";

import type { EndpointCapabilityConfig } from "./types.js";

const ISSUER = "https://signet.example.com/t/acme";
const FHIR_BASE = "https://fhir.example.com/fhir";
const URLS = endpointUrls(ISSUER);

/** A typical endpoint, optionally varied for the case under test. */
function config(
  overrides: Partial<EndpointCapabilityConfig> = {},
): EndpointCapabilityConfig {
  return defaultEndpointCapabilities(ISSUER, FHIR_BASE, overrides);
}

/** Collects the keys whose value would serialise as `null` or vanish. */
function emptyValuedKeys(document: object): string[] {
  return Object.entries(document)
    .filter(([, value]) => value === undefined || value === null)
    .map(([key]) => key);
}

describe("buildSmartConfiguration", () => {
  describe("required fields", () => {
    it("always includes the token endpoint", () => {
      expect(buildSmartConfiguration(config()).token_endpoint).toBe(URLS.token);
      const minimal = buildSmartConfiguration(
        config({
          supportsEhrLaunch: false,
          supportsStandaloneLaunch: false,
          supportsBackendServices: false,
        }),
      );
      expect(minimal.token_endpoint).toBe(URLS.token);
    });

    it("always includes capabilities, grant types and challenge methods", () => {
      const document = buildSmartConfiguration(config());
      expect(document.capabilities.length).toBeGreaterThan(0);
      expect(document.grant_types_supported.length).toBeGreaterThan(0);
      expect(document.code_challenge_methods_supported).toEqual(["S256"]);
    });

    it("keeps the required keys present even for a maximally disabled endpoint", () => {
      const document = buildSmartConfiguration(
        config({
          supportsEhrLaunch: false,
          supportsStandaloneLaunch: false,
          supportsBackendServices: false,
          supportsOpenIdConnect: false,
          allowsPublicClients: false,
          allowsConfidentialSymmetricClients: false,
          allowsConfidentialAsymmetricClients: false,
          scopesSupported: [],
        }),
      );
      for (const key of [
        "token_endpoint",
        "grant_types_supported",
        "capabilities",
        "code_challenge_methods_supported",
      ]) {
        expect(Object.keys(document)).toContain(key);
      }
      expect(document.grant_types_supported).toEqual([]);
    });
  });

  describe("PKCE", () => {
    it("advertises S256 and only S256", () => {
      expect(
        buildSmartConfiguration(config()).code_challenge_methods_supported,
      ).toEqual(["S256"]);
    });

    it("never advertises plain, whatever the configuration", () => {
      for (const overrides of [
        {},
        { allowsPublicClients: false },
        { supportsOpenIdConnect: false },
        { supportsBackendServices: false },
      ]) {
        const document = buildSmartConfiguration(config(overrides));
        expect(document.code_challenge_methods_supported).not.toContain(
          "plain",
        );
      }
    });
  });

  describe("authorization_endpoint", () => {
    it("is present when the EHR launch is supported", () => {
      const document = buildSmartConfiguration(
        config({ supportsEhrLaunch: true, supportsStandaloneLaunch: false }),
      );
      expect(document.authorization_endpoint).toBe(URLS.authorization);
    });

    it("is present when the standalone launch is supported", () => {
      const document = buildSmartConfiguration(
        config({ supportsEhrLaunch: false, supportsStandaloneLaunch: true }),
      );
      expect(document.authorization_endpoint).toBe(URLS.authorization);
    });

    it("is omitted when neither launch mode is supported", () => {
      const document = buildSmartConfiguration(
        config({ supportsEhrLaunch: false, supportsStandaloneLaunch: false }),
      );
      expect(Object.keys(document)).not.toContain("authorization_endpoint");
    });
  });

  describe("issuer and jwks_uri", () => {
    it("includes both when single sign-on is supported", () => {
      const document = buildSmartConfiguration(
        config({ supportsOpenIdConnect: true }),
      );
      expect(document.issuer).toBe(ISSUER);
      expect(document.jwks_uri).toBe(URLS.jwks);
    });

    it("omits the issuer but keeps jwks_uri without single sign-on", () => {
      const document = buildSmartConfiguration(
        config({ supportsOpenIdConnect: false }),
      );
      expect(Object.keys(document)).not.toContain("issuer");
      expect(document.jwks_uri).toBe(URLS.jwks);
    });

    it("normalises a trailing slash off the advertised issuer", () => {
      const document = buildSmartConfiguration(
        defaultEndpointCapabilities(`${ISSUER}/`, FHIR_BASE),
      );
      expect(document.issuer).toBe(ISSUER);
      expect(document.token_endpoint).toBe(URLS.token);
    });
  });

  describe("grant_types_supported", () => {
    it("offers authorization_code when a launch mode is supported", () => {
      const document = buildSmartConfiguration(
        config({ supportsBackendServices: false }),
      );
      expect(document.grant_types_supported).toEqual(["authorization_code"]);
    });

    it("offers client_credentials for backend services", () => {
      const document = buildSmartConfiguration(
        config({
          supportsEhrLaunch: false,
          supportsStandaloneLaunch: false,
          supportsBackendServices: true,
        }),
      );
      expect(document.grant_types_supported).toEqual(["client_credentials"]);
    });

    it("offers both when both are supported", () => {
      const document = buildSmartConfiguration(
        config({ supportsBackendServices: true }),
      );
      expect(document.grant_types_supported).toEqual([
        "authorization_code",
        "client_credentials",
      ]);
    });

    it("never offers a grant the endpoint does not implement", () => {
      const document = buildSmartConfiguration(
        config({ supportsBackendServices: false }),
      );
      expect(document.grant_types_supported).not.toContain(
        "client_credentials",
      );
    });
  });

  describe("token_endpoint_auth_methods_supported", () => {
    it("offers the shared secret methods for symmetric clients", () => {
      const document = buildSmartConfiguration(
        config({
          allowsConfidentialSymmetricClients: true,
          allowsConfidentialAsymmetricClients: false,
        }),
      );
      expect(document.token_endpoint_auth_methods_supported).toEqual([
        "client_secret_basic",
        "client_secret_post",
      ]);
    });

    it("offers private_key_jwt for asymmetric clients", () => {
      const document = buildSmartConfiguration(
        config({
          allowsConfidentialSymmetricClients: false,
          allowsConfidentialAsymmetricClients: true,
        }),
      );
      expect(document.token_endpoint_auth_methods_supported).toEqual([
        "private_key_jwt",
      ]);
    });

    it("offers all three when both confidential client types are allowed", () => {
      const document = buildSmartConfiguration(config());
      expect(document.token_endpoint_auth_methods_supported).toEqual([
        "client_secret_basic",
        "client_secret_post",
        "private_key_jwt",
      ]);
    });

    it("omits the field for a public-only endpoint", () => {
      const document = buildSmartConfiguration(
        config({
          allowsPublicClients: true,
          allowsConfidentialSymmetricClients: false,
          allowsConfidentialAsymmetricClients: false,
        }),
      );
      expect(Object.keys(document)).not.toContain(
        "token_endpoint_auth_methods_supported",
      );
    });
  });

  describe("registration_endpoint", () => {
    it("is present only when the endpoint names a trust anchor", () => {
      // The rule is the whole of the advertisement. An endpoint with no anchor
      // serves nothing at `/register`, so advertising it would be a promise to
      // every app that reads the document that Signet cannot keep.
      expect(
        buildSmartConfiguration(config(), {
          acceptsVouchedRegistration: true,
        }).registration_endpoint,
      ).toBe(URLS.registration);
      expect(
        Object.keys(
          buildSmartConfiguration(config(), {
            acceptsVouchedRegistration: false,
          }),
        ),
      ).not.toContain("registration_endpoint");
    });

    it("is absent by default, which is the endpoint with no anchor", () => {
      // Omitting the option must not advertise: a caller that forgot to look the
      // rule up gets the refusing answer, not the permissive one.
      expect(Object.keys(buildSmartConfiguration(config()))).not.toContain(
        "registration_endpoint",
      );
    });

    it("advertises ticket types only when the endpoint names a ticket issuer", () => {
      // The same rule as the registration endpoint above, and the same default:
      // an endpoint that has not been asked about a ticket issuer advertises no
      // ticket support and refuses the exchange grant.
      expect(
        buildSmartConfiguration(config(), {
          permissionTicketTypes: ["patient-self-access"],
        }).smart_permission_ticket_types_supported,
      ).toEqual(["patient-self-access"]);
      expect(Object.keys(buildSmartConfiguration(config()))).not.toContain(
        "smart_permission_ticket_types_supported",
      );
    });

    it("advertises nothing for a ticket rule that accepts no types", () => {
      // A rule naming no type accepts no ticket. Advertising an empty array
      // would say "exchange is supported" and then refuse every ticket.
      expect(
        Object.keys(
          buildSmartConfiguration(config(), { permissionTicketTypes: [] }),
        ),
      ).not.toContain("smart_permission_ticket_types_supported");
    });

    it("is not advertised by the developer portal's own flag", () => {
      // `supportsDynamicRegistration` turns the human-reviewed portal on. It used
      // to drive this field, and an endpoint with the portal enabled and no anchor
      // would then advertise a registration endpoint answering 404.
      expect(
        Object.keys(
          buildSmartConfiguration(
            config({ supportsDynamicRegistration: true }),
          ),
        ),
      ).not.toContain("registration_endpoint");
    });
  });

  describe("recommended fields", () => {
    it("advertises the management, introspection and revocation endpoints", () => {
      const document = buildSmartConfiguration(config());
      expect(document.management_endpoint).toBe(URLS.management);
      expect(document.introspection_endpoint).toBe(URLS.introspection);
      expect(document.revocation_endpoint).toBe(URLS.revocation);
    });

    it("advertises code as the only response type", () => {
      expect(
        buildSmartConfiguration(config()).response_types_supported,
      ).toEqual(["code"]);
    });

    it("passes the configured scopes through unchanged", () => {
      const document = buildSmartConfiguration(
        config({ scopesSupported: ["openid", "patient/Observation.rs"] }),
      );
      expect(document.scopes_supported).toEqual([
        "openid",
        "patient/Observation.rs",
      ]);
    });

    it("omits scopes_supported rather than advertising an empty list", () => {
      const document = buildSmartConfiguration(config({ scopesSupported: [] }));
      expect(Object.keys(document)).not.toContain("scopes_supported");
    });
  });

  describe("user access brand", () => {
    it("includes both brand fields when configured", () => {
      const document = buildSmartConfiguration(
        config({
          userAccessBrandBundle: "https://example.com/brand.json",
          userAccessBrandIdentifier: "acme-health",
        }),
      );
      expect(document.user_access_brand_bundle).toBe(
        "https://example.com/brand.json",
      );
      expect(document.user_access_brand_identifier).toBe("acme-health");
    });

    it("omits each brand field that is not configured", () => {
      const document = buildSmartConfiguration(
        config({ userAccessBrandBundle: "https://example.com/brand.json" }),
      );
      expect(document.user_access_brand_bundle).toBe(
        "https://example.com/brand.json",
      );
      expect(Object.keys(document)).not.toContain(
        "user_access_brand_identifier",
      );
    });

    it("omits both when neither is configured", () => {
      const keys = Object.keys(buildSmartConfiguration(config()));
      expect(keys).not.toContain("user_access_brand_bundle");
      expect(keys).not.toContain("user_access_brand_identifier");
    });
  });

  describe("serialisation", () => {
    it("has no undefined or null valued keys, for any configuration", () => {
      const variants: Partial<EndpointCapabilityConfig>[] = [
        {},
        { supportsEhrLaunch: false, supportsStandaloneLaunch: false },
        { supportsOpenIdConnect: false },
        {
          allowsConfidentialSymmetricClients: false,
          allowsConfidentialAsymmetricClients: false,
        },
        { supportsDynamicRegistration: true },
        { scopesSupported: [] },
        { userAccessBrandIdentifier: "acme-health" },
      ];
      for (const overrides of variants) {
        const document = buildSmartConfiguration(config(overrides));
        expect(emptyValuedKeys(document)).toEqual([]);
        // A round trip through JSON must not lose or add a key.
        const json = JSON.stringify(document);
        const parsed = JSON.parse(json) as Record<string, unknown>;
        expect(Object.keys(parsed)).toEqual(Object.keys(document));
      }

      // The one field that comes from a rule rather than a column, checked the
      // same way: an advertised registration endpoint is a string, never a null.
      expect(
        emptyValuedKeys(
          buildSmartConfiguration(config(), {
            acceptsVouchedRegistration: true,
          }),
        ),
      ).toEqual([]);
    });

    it("does not leak an omitted key into the serialised JSON", () => {
      const json = JSON.stringify(
        buildSmartConfiguration(
          config({ supportsEhrLaunch: false, supportsStandaloneLaunch: false }),
        ),
      );
      expect(json).not.toContain("authorization_endpoint");
      expect(json).not.toContain("undefined");
      expect(json).not.toContain("null");
    });

    it("is deterministic: the same configuration serialises identically", () => {
      expect(JSON.stringify(buildSmartConfiguration(config()))).toBe(
        JSON.stringify(buildSmartConfiguration(config())),
      );
    });
  });

  it("derives capabilities from the same configuration", () => {
    const document = buildSmartConfiguration(
      config({ supportsStyling: false }),
    );
    expect(document.capabilities).not.toContain("context-style");
  });
});

describe("buildOpenIdConfiguration", () => {
  it("fills in every endpoint the document requires", () => {
    const document = buildOpenIdConfiguration(config());
    expect(document.issuer).toBe(ISSUER);
    expect(document.authorization_endpoint).toBe(URLS.authorization);
    expect(document.token_endpoint).toBe(URLS.token);
    expect(document.jwks_uri).toBe(URLS.jwks);
    expect(document.introspection_endpoint).toBe(URLS.introspection);
    expect(document.revocation_endpoint).toBe(URLS.revocation);
  });

  it("normalises a trailing slash off the issuer", () => {
    const document = buildOpenIdConfiguration(
      defaultEndpointCapabilities(`${ISSUER}/`, FHIR_BASE),
    );
    expect(document.issuer).toBe(ISSUER);
    expect(document.jwks_uri).toBe(URLS.jwks);
  });

  it("falls back to the SMART algorithms for an endpoint with no keys", () => {
    expect(
      buildOpenIdConfiguration(config()).id_token_signing_alg_values_supported,
    ).toEqual(["RS384", "ES384"]);
    expect(
      buildOpenIdConfiguration(config(), { signingAlgorithms: [] })
        .id_token_signing_alg_values_supported,
    ).toEqual(["RS384", "ES384"]);
  });

  it("advertises the algorithms the endpoint's own keys use", () => {
    // The property that matters: a relying party configuring a verifier from this
    // document must end up accepting exactly what the endpoint signs with. An
    // endpoint on RS256 - the compatibility choice for a Spring-based resource
    // server - must not advertise RS384.
    expect(
      buildOpenIdConfiguration(config(), { signingAlgorithms: ["RS256"] })
        .id_token_signing_alg_values_supported,
    ).toEqual(["RS256"]);
  });

  it("advertises public subject types only", () => {
    expect(buildOpenIdConfiguration(config()).subject_types_supported).toEqual([
      "public",
    ]);
  });

  it("advertises S256 as the only challenge method", () => {
    const document = buildOpenIdConfiguration(config());
    expect(document.code_challenge_methods_supported).toEqual(["S256"]);
    expect(document.code_challenge_methods_supported).not.toContain("plain");
  });

  it("advertises code as the only response type", () => {
    expect(buildOpenIdConfiguration(config()).response_types_supported).toEqual(
      ["code"],
    );
  });

  it("advertises the claims Signet puts in an ID token", () => {
    expect(buildOpenIdConfiguration(config()).claims_supported).toEqual([
      "sub",
      "iss",
      "aud",
      "exp",
      "iat",
      "fhirUser",
      "profile",
    ]);
  });

  it("includes the userinfo endpoint when single sign-on is supported", () => {
    expect(
      buildOpenIdConfiguration(config({ supportsOpenIdConnect: true }))
        .userinfo_endpoint,
    ).toBe(URLS.userinfo);
  });

  it("omits the userinfo endpoint without single sign-on", () => {
    const document = buildOpenIdConfiguration(
      config({ supportsOpenIdConnect: false }),
    );
    expect(Object.keys(document)).not.toContain("userinfo_endpoint");
  });

  it("includes the registration endpoint only when the endpoint names a trust anchor", () => {
    expect(
      buildOpenIdConfiguration(config(), { acceptsVouchedRegistration: true })
        .registration_endpoint,
    ).toBe(URLS.registration);
    expect(
      Object.keys(
        buildOpenIdConfiguration(config(), {
          acceptsVouchedRegistration: false,
        }),
      ),
    ).not.toContain("registration_endpoint");
    // Both documents answer the same question the same way; a resource server
    // that merges from this one must not see a registration endpoint that the
    // SMART document does not advertise.
    expect(
      Object.keys(
        buildOpenIdConfiguration(config({ supportsDynamicRegistration: true })),
      ),
    ).not.toContain("registration_endpoint");
  });

  describe("grant_types_supported", () => {
    it("lists refresh_token when a refresh scope is on offer", () => {
      const document = buildOpenIdConfiguration(
        config({ supportsOfflineAccess: true, supportsOnlineAccess: false }),
      );
      expect(document.grant_types_supported).toEqual([
        "authorization_code",
        "client_credentials",
        "refresh_token",
      ]);
    });

    it("lists refresh_token for online access alone", () => {
      const document = buildOpenIdConfiguration(
        config({ supportsOfflineAccess: false, supportsOnlineAccess: true }),
      );
      expect(document.grant_types_supported).toContain("refresh_token");
    });

    it("omits refresh_token when neither refresh scope is offered", () => {
      const document = buildOpenIdConfiguration(
        config({ supportsOfflineAccess: false, supportsOnlineAccess: false }),
      );
      expect(document.grant_types_supported).not.toContain("refresh_token");
    });

    it("agrees with the smart-configuration on the OAuth grants", () => {
      const endpoint = config({ supportsBackendServices: false });
      const openId = buildOpenIdConfiguration(endpoint);
      const smart = buildSmartConfiguration(endpoint);
      for (const grant of smart.grant_types_supported) {
        expect(openId.grant_types_supported).toContain(grant);
      }
      expect(openId.grant_types_supported).not.toContain("client_credentials");
    });
  });

  describe("token_endpoint_auth_methods_supported", () => {
    it("covers every client type allowed, including `none` for public clients", () => {
      expect(
        buildOpenIdConfiguration(config())
          .token_endpoint_auth_methods_supported,
      ).toEqual([
        "none",
        "client_secret_basic",
        "client_secret_post",
        "private_key_jwt",
      ]);
    });

    it("reports `none` for a public-only endpoint rather than an empty list", () => {
      // An empty array would read as "no client may authenticate at all". `none`
      // is the OIDC value for a client that authenticates with PKCE instead of a
      // credential.
      expect(
        buildOpenIdConfiguration(
          config({
            allowsConfidentialSymmetricClients: false,
            allowsConfidentialAsymmetricClients: false,
          }),
        ).token_endpoint_auth_methods_supported,
      ).toEqual(["none"]);
    });

    it("omits `none` from the SMART document, whose enumeration does not define it", () => {
      // SMART lists only client_secret_post, client_secret_basic and
      // private_key_jwt, so leaking `none` there would be non-conformant.
      const smart = buildSmartConfiguration(config());
      expect(smart.token_endpoint_auth_methods_supported).not.toContain("none");
      expect(
        buildSmartConfiguration(
          config({
            allowsConfidentialSymmetricClients: false,
            allowsConfidentialAsymmetricClients: false,
          }),
        ).token_endpoint_auth_methods_supported,
      ).toBeUndefined();
    });
  });

  describe("serialisation", () => {
    it("has no undefined or null valued keys, for any configuration", () => {
      const variants: Partial<EndpointCapabilityConfig>[] = [
        {},
        { supportsOpenIdConnect: false },
        { supportsDynamicRegistration: true },
        { scopesSupported: [] },
        { supportsOfflineAccess: false, supportsOnlineAccess: false },
      ];
      for (const overrides of variants) {
        const document = buildOpenIdConfiguration(config(overrides));
        expect(emptyValuedKeys(document)).toEqual([]);
      }
    });

    it("passes the configured scopes through, even when empty", () => {
      // Unlike smart-configuration, the field is required here, so an endpoint
      // granting nothing advertises an empty list rather than dropping the key.
      const document = buildOpenIdConfiguration(
        config({ scopesSupported: [] }),
      );
      expect(document.scopes_supported).toEqual([]);
    });

    it("is complete enough for a resource server to merge from", () => {
      // Pathling reads these fields to synthesise its own SMART configuration.
      const document = buildOpenIdConfiguration(config());
      for (const key of [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "scopes_supported",
        "response_types_supported",
        "grant_types_supported",
        "code_challenge_methods_supported",
      ]) {
        expect(Object.keys(document)).toContain(key);
      }
    });
  });
});
