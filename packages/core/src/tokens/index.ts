/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

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
