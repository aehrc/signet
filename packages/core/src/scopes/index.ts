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
