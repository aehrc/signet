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
