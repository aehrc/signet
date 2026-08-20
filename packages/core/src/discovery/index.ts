/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

export { buildOpenIdConfiguration, buildSmartConfiguration } from "./build.js";
export {
  DEFAULT_ENDPOINT_CAPABILITIES,
  DEFAULT_SCOPES_SUPPORTED,
  defaultEndpointCapabilities,
  deriveCapabilities,
} from "./capabilities.js";
export {
  endpointUrls,
  normaliseIssuer,
  type EndpointUrls,
} from "./endpoints.js";
export type {
  EndpointCapabilityConfig,
  OpenIdConfiguration,
  SmartCapability,
  SmartConfiguration,
  TokenEndpointAuthMethod,
} from "./types.js";
