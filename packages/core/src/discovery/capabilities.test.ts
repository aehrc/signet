/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  DEFAULT_ENDPOINT_CAPABILITIES,
  DEFAULT_SCOPES_SUPPORTED,
  defaultEndpointCapabilities,
  deriveCapabilities,
} from "./capabilities.js";
import { parseScopes } from "../scopes/parse.js";
import { formatScopes } from "../scopes/serialise.js";

import type { EndpointCapabilityConfig, SmartCapability } from "./types.js";

const ISSUER = "https://signet.example.com/t/acme";
const FHIR_BASE = "https://fhir.example.com/fhir";

/** An endpoint that supports nothing at all: the baseline for each flag test. */
const NOTHING: EndpointCapabilityConfig = {
  issuer: ISSUER,
  fhirBaseUrl: FHIR_BASE,

  supportsEhrLaunch: false,
  supportsStandaloneLaunch: false,
  supportsAuthorizePost: false,

  allowsPublicClients: false,
  allowsConfidentialSymmetricClients: false,
  allowsConfidentialAsymmetricClients: false,

  supportsOpenIdConnect: false,

  supportsPatientBanner: false,
  supportsStyling: false,

  supportsEhrPatientContext: false,
  supportsEhrEncounterContext: false,
  supportsStandalonePatientContext: false,
  supportsStandaloneEncounterContext: false,

  supportsOfflineAccess: false,
  supportsOnlineAccess: false,
  supportsPatientScopes: false,
  supportsUserScopes: false,
  supportsV1Scopes: false,
  supportsV2Scopes: false,

  supportsBackendServices: false,

  scopesSupported: [],

  supportsDynamicRegistration: false,
};

/** Every flag on, so the full capability list is produced. */
const EVERYTHING: EndpointCapabilityConfig = {
  ...NOTHING,
  supportsEhrLaunch: true,
  supportsStandaloneLaunch: true,
  supportsAuthorizePost: true,
  allowsPublicClients: true,
  allowsConfidentialSymmetricClients: true,
  allowsConfidentialAsymmetricClients: true,
  supportsOpenIdConnect: true,
  supportsPatientBanner: true,
  supportsStyling: true,
  supportsEhrPatientContext: true,
  supportsEhrEncounterContext: true,
  supportsStandalonePatientContext: true,
  supportsStandaloneEncounterContext: true,
  supportsOfflineAccess: true,
  supportsOnlineAccess: true,
  supportsPatientScopes: true,
  supportsUserScopes: true,
  supportsV1Scopes: true,
  supportsV2Scopes: true,
  supportsBackendServices: true,
  supportsDynamicRegistration: true,
};

/** One row per capability: the flag that enables it, and the string it emits. */
const FLAG_TO_CAPABILITY: readonly (readonly [
  keyof EndpointCapabilityConfig,
  SmartCapability,
])[] = [
  ["supportsEhrLaunch", "launch-ehr"],
  ["supportsStandaloneLaunch", "launch-standalone"],
  ["supportsAuthorizePost", "authorize-post"],
  ["allowsPublicClients", "client-public"],
  ["allowsConfidentialSymmetricClients", "client-confidential-symmetric"],
  ["allowsConfidentialAsymmetricClients", "client-confidential-asymmetric"],
  ["supportsOpenIdConnect", "sso-openid-connect"],
  ["supportsPatientBanner", "context-banner"],
  ["supportsStyling", "context-style"],
  ["supportsEhrPatientContext", "context-ehr-patient"],
  ["supportsEhrEncounterContext", "context-ehr-encounter"],
  ["supportsStandalonePatientContext", "context-standalone-patient"],
  ["supportsStandaloneEncounterContext", "context-standalone-encounter"],
  ["supportsOfflineAccess", "permission-offline"],
  ["supportsOnlineAccess", "permission-online"],
  ["supportsPatientScopes", "permission-patient"],
  ["supportsUserScopes", "permission-user"],
  ["supportsV1Scopes", "permission-v1"],
  ["supportsV2Scopes", "permission-v2"],
];

describe("deriveCapabilities", () => {
  it("advertises nothing when nothing is supported", () => {
    expect(deriveCapabilities(NOTHING)).toEqual([]);
  });

  it.each(FLAG_TO_CAPABILITY)(
    "advertises only %s => %s when that flag alone is set",
    (flag, capability) => {
      const config: EndpointCapabilityConfig = { ...NOTHING, [flag]: true };
      expect(deriveCapabilities(config)).toEqual([capability]);
    },
  );

  it.each(FLAG_TO_CAPABILITY)(
    "omits %s => %s when the flag is cleared from a fully enabled endpoint",
    (flag, capability) => {
      const config: EndpointCapabilityConfig = { ...EVERYTHING, [flag]: false };
      expect(deriveCapabilities(config)).not.toContain(capability);
    },
  );

  it("advertises every capability in spec order when all are supported", () => {
    expect(deriveCapabilities(EVERYTHING)).toEqual(
      FLAG_TO_CAPABILITY.map(([, capability]) => capability),
    );
  });

  it("does not treat dynamic registration or backend services as capabilities", () => {
    // Neither has a SMART capability string; they surface as endpoints and
    // grant types instead.
    const config: EndpointCapabilityConfig = {
      ...NOTHING,
      supportsBackendServices: true,
      supportsDynamicRegistration: true,
    };
    expect(deriveCapabilities(config)).toEqual([]);
  });

  it("orders capabilities independently of the order of the configuration keys", () => {
    // The same flags declared in reverse order must still serialise the same.
    const reversed: EndpointCapabilityConfig = {
      ...NOTHING,
      supportsV2Scopes: true,
      supportsOpenIdConnect: true,
      supportsEhrLaunch: true,
    };
    expect(deriveCapabilities(reversed)).toEqual([
      "launch-ehr",
      "sso-openid-connect",
      "permission-v2",
    ]);
  });

  it("never emits a duplicate capability", () => {
    const capabilities = deriveCapabilities(EVERYTHING);
    expect(new Set(capabilities).size).toBe(capabilities.length);
  });
});

describe("DEFAULT_SCOPES_SUPPORTED", () => {
  it("contains only scopes the scope parser accepts", () => {
    const result = parseScopes(DEFAULT_SCOPES_SUPPORTED.join(" "));
    expect(result.rejected).toEqual([]);
    expect(result.scopes).toHaveLength(DEFAULT_SCOPES_SUPPORTED.length);
  });

  it("is already in canonical v2 form, so it round-trips unchanged", () => {
    const result = parseScopes(DEFAULT_SCOPES_SUPPORTED.join(" "));
    expect(formatScopes(result.scopes)).toBe(
      DEFAULT_SCOPES_SUPPORTED.join(" "),
    );
  });

  it("offers identity, refresh, launch and resource scopes", () => {
    expect(DEFAULT_SCOPES_SUPPORTED).toContain("openid");
    expect(DEFAULT_SCOPES_SUPPORTED).toContain("fhirUser");
    expect(DEFAULT_SCOPES_SUPPORTED).toContain("offline_access");
    expect(DEFAULT_SCOPES_SUPPORTED).toContain("launch");
    expect(DEFAULT_SCOPES_SUPPORTED).toContain("launch/patient");
    expect(DEFAULT_SCOPES_SUPPORTED).toContain("patient/*.rs");
    expect(DEFAULT_SCOPES_SUPPORTED).toContain("user/*.rs");
    expect(DEFAULT_SCOPES_SUPPORTED).toContain("system/*.rs");
  });

  it("does not offer write access by default", () => {
    for (const scope of DEFAULT_SCOPES_SUPPORTED) {
      expect(scope).not.toMatch(/\.[a-z]*[cud]/);
    }
  });
});

describe("DEFAULT_ENDPOINT_CAPABILITIES", () => {
  it("keeps dynamic registration off, since it is opt-in per tenant", () => {
    expect(DEFAULT_ENDPOINT_CAPABILITIES.supportsDynamicRegistration).toBe(
      false,
    );
  });

  it("supports both launch modes and single sign-on", () => {
    expect(DEFAULT_ENDPOINT_CAPABILITIES.supportsEhrLaunch).toBe(true);
    expect(DEFAULT_ENDPOINT_CAPABILITIES.supportsStandaloneLaunch).toBe(true);
    expect(DEFAULT_ENDPOINT_CAPABILITIES.supportsOpenIdConnect).toBe(true);
  });
});

describe("defaultEndpointCapabilities", () => {
  it("fills in the issuer and FHIR base URL", () => {
    const config = defaultEndpointCapabilities(ISSUER, FHIR_BASE);
    expect(config.issuer).toBe(ISSUER);
    expect(config.fhirBaseUrl).toBe(FHIR_BASE);
  });

  it("carries the default flags through", () => {
    const config = defaultEndpointCapabilities(ISSUER, FHIR_BASE);
    expect(config.supportsV2Scopes).toBe(true);
    expect(config.scopesSupported).toEqual(DEFAULT_SCOPES_SUPPORTED);
  });

  it("lets overrides win over the defaults", () => {
    const config = defaultEndpointCapabilities(ISSUER, FHIR_BASE, {
      supportsDynamicRegistration: true,
      supportsOpenIdConnect: false,
      scopesSupported: ["patient/Observation.rs"],
    });
    expect(config.supportsDynamicRegistration).toBe(true);
    expect(config.supportsOpenIdConnect).toBe(false);
    expect(config.scopesSupported).toEqual(["patient/Observation.rs"]);
  });

  it("derives a capability list consistent with its own flags", () => {
    const config = defaultEndpointCapabilities(ISSUER, FHIR_BASE);
    const capabilities = deriveCapabilities(config);
    expect(capabilities).toContain("launch-ehr");
    expect(capabilities).toContain("sso-openid-connect");
    expect(capabilities).not.toContain("context-style");
  });
});
