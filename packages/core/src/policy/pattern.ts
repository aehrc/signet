/**
 * Author: John Grimes
 */

import { parseScope } from "../scopes/index.js";

import type { ParsedScopePattern, ScopePattern } from "./types.js";
import type {
  Permission,
  ResourceScope,
  Scope,
  ScopeContext,
} from "../scopes/types.js";

/** Contexts a pattern may name, including the wildcard. */
const PATTERN_CONTEXTS = new Set<string>(["patient", "user", "system", "*"]);

/**
 * Parses a scope pattern of the form `{context|*}/{ResourceType|*}.{permissions}`.
 *
 * The resource type and permission grammar is delegated to {@link parseScope},
 * so a pattern can never accept a shape a real scope could not take - including
 * the v1 suffixes, meaning `patient/*.read` is a legal pattern equivalent to
 * `patient/*.rs`.
 *
 * Search parameter restrictions are deliberately rejected: {@link
 * ParsedScopePattern} has nowhere to put them, and silently ignoring a `?`
 * clause would make a pattern match strictly more scopes than its author wrote.
 *
 * @param pattern - The pattern to parse.
 * @returns The parsed pattern, or `undefined` when it is not a resource pattern.
 */
export function parseScopePattern(
  pattern: ScopePattern,
): ParsedScopePattern | undefined {
  if (pattern.includes("?")) {
    return undefined;
  }

  const slash = pattern.indexOf("/");
  if (slash === -1) {
    return undefined;
  }

  const context = pattern.slice(0, slash);
  if (!PATTERN_CONTEXTS.has(context)) {
    return undefined;
  }

  // A wildcard context is probed as `patient` purely to reuse the scope parser;
  // the wildcard is restored on the way out.
  const probeContext = context === "*" ? "patient" : context;
  const probe = parseScope(`${probeContext}/${pattern.slice(slash + 1)}`);
  if (!probe.ok || probe.scope.kind !== "resource") {
    return undefined;
  }

  return {
    context: context === "*" ? "*" : (context as ScopeContext),
    resourceType: probe.scope.resourceType,
    permissions: probe.scope.permissions,
  };
}

/**
 * True when the scope's context and resource type fall inside the pattern's.
 *
 * Shared by both matching modes, which differ only in how they compare
 * permissions.
 */
function targetMatches(
  scope: Scope,
  pattern: ParsedScopePattern,
): scope is ResourceScope {
  // Only resource scopes have a context and resource type, so launch, identity,
  // refresh and custom scopes can never match a pattern. Those are handled by
  // exact string equality elsewhere.
  if (scope.kind !== "resource") {
    return false;
  }
  if (pattern.context !== "*" && pattern.context !== scope.context) {
    return false;
  }
  // Note the asymmetry: `patient/Observation.r` does not match the scope
  // `patient/*.r`. A wildcard scope asks for more than the pattern names, and a
  // grant rule must not be fooled into covering it.
  return (
    pattern.resourceType === "*" || pattern.resourceType === scope.resourceType
  );
}

/**
 * True when the scope asks for no more than the pattern permits.
 *
 * This is **within** matching, used by grant rules and conditions: the scope's
 * permissions must be a subset of the pattern's, so `patient/*.rs` matches
 * `patient/Observation.r` but not `patient/Observation.cud`.
 *
 * @param scope - The scope under consideration.
 * @param pattern - The parsed pattern to test against.
 */
export function scopeMatchesWithin(
  scope: Scope,
  pattern: ParsedScopePattern,
): boolean {
  if (!targetMatches(scope, pattern)) {
    return false;
  }
  const permitted = new Set<Permission>(pattern.permissions);
  return scope.permissions.every((permission) => permitted.has(permission));
}

/**
 * True when the scope shares at least one permission with the pattern.
 *
 * This is **intersects** matching, used by scope mapping rules: the any-context
 * read pattern `*\/*.r` matches `patient/Observation.rs` because both mention
 * `r`, which is the right question when asking "does this scope imply a read
 * authority?".
 *
 * @param scope - The scope under consideration.
 * @param pattern - The parsed pattern to test against.
 */
export function scopeMatchesIntersects(
  scope: Scope,
  pattern: ParsedScopePattern,
): boolean {
  if (!targetMatches(scope, pattern)) {
    return false;
  }
  const wanted = new Set<Permission>(pattern.permissions);
  return scope.permissions.some((permission) => wanted.has(permission));
}

/**
 * Reduces a scope to the permissions a pattern permits, or returns `undefined`
 * when no reduction is possible.
 *
 * Returns `undefined` for a non-resource scope, for a context or resource type
 * that does not match, when the overlap is empty, and - deliberately - when the
 * scope already satisfies the pattern under **within** matching. In that last
 * case there is nothing to narrow, and the caller should treat it as an ordinary
 * match rather than a narrowing.
 *
 * Search parameter restrictions on the requested scope are preserved: they only
 * ever reduce access further, so dropping them would widen the grant.
 *
 * @param scope - The requested scope.
 * @param pattern - The parsed pattern bounding what may be granted.
 */
export function narrowScopeToPattern(
  scope: Scope,
  pattern: ParsedScopePattern,
): ResourceScope | undefined {
  if (scope.kind !== "resource" || !targetMatches(scope, pattern)) {
    return undefined;
  }
  const permitted = new Set<Permission>(pattern.permissions);
  const overlap = scope.permissions.filter((permission) =>
    permitted.has(permission),
  );
  if (overlap.length === 0 || overlap.length === scope.permissions.length) {
    return undefined;
  }
  return { ...scope, permissions: overlap };
}
