/**
 * Author: John Grimes
 */

export {
  assembleAccessTokenClaims,
  assembleIdTokenClaims,
  assembleTokenResponse,
  type IdTokenInput,
} from "./assemble.js";
export { buildIntrospectionResponse } from "./introspect.js";
export {
  simulateIssuance,
  type SimulationInput,
  type SimulationResult,
} from "./simulate.js";
export type {
  AccessTokenClaims,
  AccessTokenInput,
  IdTokenClaims,
  IntrospectableToken,
  IntrospectionResponse,
  RegisteredClaims,
  TokenIssuanceParameters,
  TokenResponse,
  TokenResponseInput,
} from "./types.js";
