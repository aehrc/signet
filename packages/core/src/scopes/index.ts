/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

export { parseScope, parseScopes, type ParseScopesResult } from "./parse.js";
export { formatScope, formatScopes } from "./serialise.js";
export {
  areScopesCoveredBy,
  isScopeCoveredBy,
  isScopeSubsetOf,
  narrowToPermitted,
} from "./subset.js";
export {
  PERMISSION_ORDER,
  type CustomScope,
  type IdentityScope,
  type LaunchScope,
  type Permission,
  type RefreshScope,
  type ResourceScope,
  type Scope,
  type ScopeContext,
  type ScopeParameter,
  type ScopeParseErrorCode,
  type ScopeParseResult,
} from "./types.js";
