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
