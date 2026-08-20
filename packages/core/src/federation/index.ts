/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

export {
  federatedUsername,
  mapUpstreamClaims,
  mergeClaims,
  readRoles,
  type ClaimMappings,
  type MappedIdentity,
} from "./claims.js";
export {
  UPSTREAM_ID_TOKEN_CLOCK_SKEW_SECONDS,
  MAX_UPSTREAM_ID_TOKEN_AGE_SECONDS,
  validateUpstreamIdToken,
  type UpstreamIdTokenClaims,
  type UpstreamIdTokenInput,
  type UpstreamIdTokenRefusalCode,
  type UpstreamIdTokenValidation,
  type ValidatedUpstreamIdToken,
} from "./idToken.js";
export {
  supportsPkce,
  validateUpstreamMetadata,
  type MetadataRefusalCode,
  type MetadataValidation,
  type UpstreamMetadata,
} from "./metadata.js";
