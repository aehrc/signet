/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { formatScopes } from "../scopes/serialise.js";

import type { EndpointCapabilityConfig, SmartCapability } from "./types.js";
import type { Scope } from "../scopes/types.js";

/**
 * The capability strings, in spec declaration order, paired with the flag on
 * {@link EndpointCapabilityConfig} that turns each one on.
 *
 * Keeping this a single table is the whole point of the module: Signet cannot
 * advertise a capability it does not implement, because the only way a
 * capability reaches the discovery document is by a configuration flag being
 * set, and the only way a flag exists is by an endpoint honouring it.
 */
const CAPABILITY_FLAGS: readonly (readonly [
  SmartCapability,
  keyof EndpointCapabilityConfig,
])[] = [
  ["launch-ehr", "supportsEhrLaunch"],
  ["launch-standalone", "supportsStandaloneLaunch"],
  ["authorize-post", "supportsAuthorizePost"],
  ["client-public", "allowsPublicClients"],
  ["client-confidential-symmetric", "allowsConfidentialSymmetricClients"],
  ["client-confidential-asymmetric", "allowsConfidentialAsymmetricClients"],
  ["sso-openid-connect", "supportsOpenIdConnect"],
  ["context-banner", "supportsPatientBanner"],
  ["context-style", "supportsStyling"],
  ["context-ehr-patient", "supportsEhrPatientContext"],
  ["context-ehr-encounter", "supportsEhrEncounterContext"],
  ["context-standalone-patient", "supportsStandalonePatientContext"],
  ["context-standalone-encounter", "supportsStandaloneEncounterContext"],
  ["permission-offline", "supportsOfflineAccess"],
  ["permission-online", "supportsOnlineAccess"],
  ["permission-patient", "supportsPatientScopes"],
  ["permission-user", "supportsUserScopes"],
  ["permission-v1", "supportsV1Scopes"],
  ["permission-v2", "supportsV2Scopes"],
  // `smart-app-state` is deliberately absent. The capability means the server
  // persists app state at an endpoint it advertises, and Signet advertises no
  // such endpoint - so a flag for it would let an operator publish a claim
  // nothing here honours, which is the exact failure this table exists to make
  // impossible.
];

/**
 * Derives the `capabilities` array from an endpoint's configuration.
 *
 * The order is fixed by {@link CAPABILITY_FLAGS} rather than by the order of
 * the configuration object, so two endpoints with the same behaviour always
 * produce byte-identical documents and diffs stay readable.
 *
 * @param config - The endpoint configuration.
 */
export function deriveCapabilities(
  config: EndpointCapabilityConfig,
): readonly SmartCapability[] {
  return CAPABILITY_FLAGS.filter(([, flag]) => config[flag] === true).map(
    ([capability]) => capability,
  );
}

/**
 * The scopes a typical Signet endpoint is willing to grant, as parsed scopes so
 * that the advertised strings are always in canonical v2 form.
 */
const DEFAULT_SCOPES: readonly Scope[] = [
  { kind: "identity", name: "openid" },
  { kind: "identity", name: "fhirUser" },
  { kind: "identity", name: "profile" },
  { kind: "refresh", name: "offline_access" },
  { kind: "refresh", name: "online_access" },
  { kind: "launch" },
  { kind: "launch", resource: "patient" },
  { kind: "launch", resource: "encounter" },
  {
    kind: "resource",
    context: "patient",
    resourceType: "*",
    permissions: ["r", "s"],
    parameters: [],
  },
  {
    kind: "resource",
    context: "user",
    resourceType: "*",
    permissions: ["r", "s"],
    parameters: [],
  },
  {
    kind: "resource",
    context: "system",
    resourceType: "*",
    permissions: ["r", "s"],
    parameters: [],
  },
];

/** The default `scopes_supported` list, as canonical scope strings. */
export const DEFAULT_SCOPES_SUPPORTED: readonly string[] =
  formatScopes(DEFAULT_SCOPES).split(" ");

/**
 * The capability profile of a typical Signet endpoint: both launch modes, all
 * three client types, OpenID Connect, and read/search access.
 *
 * Dynamic registration is deliberately off - it is opt-in per tenant - and so
 * is app state, which needs storage that not every deployment provides.
 */
export const DEFAULT_ENDPOINT_CAPABILITIES: Omit<
  EndpointCapabilityConfig,
  "issuer" | "fhirBaseUrl"
> = {
  supportsEhrLaunch: true,
  supportsStandaloneLaunch: true,
  supportsAuthorizePost: true,

  allowsPublicClients: true,
  allowsConfidentialSymmetricClients: true,
  allowsConfidentialAsymmetricClients: true,

  supportsOpenIdConnect: true,

  supportsPatientBanner: true,
  supportsStyling: false,

  supportsEhrPatientContext: true,
  supportsEhrEncounterContext: true,
  supportsStandalonePatientContext: true,
  supportsStandaloneEncounterContext: false,

  supportsOfflineAccess: true,
  supportsOnlineAccess: true,
  supportsPatientScopes: true,
  supportsUserScopes: true,
  supportsV1Scopes: true,
  supportsV2Scopes: true,

  supportsBackendServices: true,

  scopesSupported: DEFAULT_SCOPES_SUPPORTED,

  supportsDynamicRegistration: false,
};

/**
 * Builds a complete configuration for a typical endpoint, so callers only have
 * to state the parts that are genuinely tenant-specific.
 *
 * @param issuer - The tenant's issuer identifier.
 * @param fhirBaseUrl - The FHIR server this endpoint protects.
 * @param overrides - Any flags to change from the defaults.
 */
export function defaultEndpointCapabilities(
  issuer: string,
  fhirBaseUrl: string,
  overrides: Partial<EndpointCapabilityConfig> = {},
): EndpointCapabilityConfig {
  return {
    ...DEFAULT_ENDPOINT_CAPABILITIES,
    issuer,
    fhirBaseUrl,
    ...overrides,
  };
}
