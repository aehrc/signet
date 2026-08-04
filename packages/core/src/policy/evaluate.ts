/**
 * Author: John Grimes
 */

import {
  narrowScopeToPattern,
  parseScopePattern,
  scopeMatchesIntersects,
  scopeMatchesWithin,
} from "./pattern.js";
import { renderTemplate, renderTemplateValue } from "./template.js";
import { formatScope } from "../scopes/index.js";

import type { TemplateScope } from "./template.js";
import type {
  DeniedScope,
  EvaluationContext,
  NarrowedScope,
  ParsedScopePattern,
  PolicyDocument,
  PolicyEvaluation,
  RuleCondition,
  ScopeGrantRule,
  ScopePattern,
  TemplateValue,
} from "./types.js";
import type { LaunchContext } from "../launch/types.js";
import type { ResourceScope, Scope } from "../scopes/types.js";

/** Which permission comparison a pattern is being used for. */
type MatchMode = "within" | "intersects";

/** The outcome of running a scope past the grant rules. */
type GrantDecision =
  | {
      readonly allow: true;
      /** Present when the scope was granted in reduced form. */
      readonly narrowedTo?: ResourceScope;
      readonly ruleId?: string;
    }
  | {
      readonly allow: false;
      readonly reason: string;
      readonly ruleId?: string;
    };

/** True when a launch context key is present and carries a usable value. */
function hasContextValue(
  context: LaunchContext,
  key: keyof LaunchContext,
): boolean {
  const value = context[key];
  if (value === undefined || value === null) {
    return false;
  }
  if (typeof value === "string") {
    return value.length > 0;
  }
  if (Array.isArray(value)) {
    return value.length > 0;
  }
  return true;
}

/**
 * Exposes a matching scope to templates.
 *
 * `resourceTypeSuffix` exists so a single mapping rule can emit an authority for
 * both a wildcard and a concrete type: `pathling:read{{ scope.resourceTypeSuffix
 * }}` renders as `pathling:read` for `system/*.r` and `pathling:read:Observation`
 * for `patient/Observation.r`.
 */
function scopeVariables(scope: Scope): Readonly<Record<string, unknown>> {
  const value = formatScope(scope);
  if (scope.kind !== "resource") {
    return {
      value,
      kind: scope.kind,
      permissions: [],
      isWildcard: false,
      resourceTypeSuffix: "",
    };
  }
  const isWildcard = scope.resourceType === "*";
  return {
    value,
    kind: scope.kind,
    context: scope.context,
    resourceType: scope.resourceType,
    permissions: [...scope.permissions],
    isWildcard,
    resourceTypeSuffix: isWildcard ? "" : `:${scope.resourceType}`,
  };
}

/** Builds the variables visible to a template, optionally binding a scope. */
function buildTemplateScope(
  context: EvaluationContext,
  granted: readonly string[],
  scope?: Scope,
): TemplateScope {
  const user = context.user;
  const base: Record<string, unknown> = {
    endpoint: {
      tenantSlug: context.endpoint.tenantSlug,
      slug: context.endpoint.slug,
      issuer: context.endpoint.issuer,
      fhirBaseUrl: context.endpoint.fhirBaseUrl,
    },
    client: {
      clientId: context.client.clientId,
      name: context.client.name,
      type: context.client.type,
      attributes: context.client.attributes,
    },
    user:
      user === null
        ? undefined
        : {
            id: user.id,
            fhirUser: user.fhirUser,
            displayName: user.displayName,
            roles: [...user.roles],
            attributes: user.attributes,
          },
    context: context.context,
    granted,
    grantType: context.grantType,
  };
  if (scope !== undefined) {
    base["scope"] = scopeVariables(scope);
  }
  return base;
}

/** Flattens a rendered mapping value into the strings to append. */
function toAppendable(value: TemplateValue | undefined): readonly string[] {
  if (value === undefined || value === null) {
    return [];
  }
  if (typeof value === "string") {
    return value.length > 0 ? [value] : [];
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return [String(value)];
  }
  if (Array.isArray(value)) {
    const entries: string[] = [];
    for (const entry of value as readonly TemplateValue[]) {
      entries.push(...toAppendable(entry));
    }
    return entries;
  }
  return [];
}

/** Removes repeats while preserving the order values were first seen in. */
function dedupe(values: readonly string[]): readonly string[] {
  const seen = new Set<string>();
  const unique: string[] = [];
  for (const value of values) {
    if (!seen.has(value)) {
      seen.add(value);
      unique.push(value);
    }
  }
  return unique;
}

/**
 * Reads an existing claim as the starting contents of an array claim.
 *
 * A claim rule may seed an array before mappings append to it, and a scalar is
 * promoted rather than discarded so that no configured value is silently lost.
 */
function seedValues(existing: unknown): readonly string[] {
  if (Array.isArray(existing)) {
    const entries: string[] = [];
    for (const entry of existing as readonly unknown[]) {
      if (typeof entry === "string") {
        entries.push(entry);
      } else if (typeof entry === "number" || typeof entry === "boolean") {
        entries.push(String(entry));
      }
    }
    return entries;
  }
  if (
    typeof existing === "string" ||
    typeof existing === "number" ||
    typeof existing === "boolean"
  ) {
    return [String(existing)];
  }
  return [];
}

/**
 * Evaluates a policy against one authorization.
 *
 * Pure: every input arrives as a parameter, so the console's policy simulator
 * runs exactly the code that issues real tokens.
 *
 * The order of operations is load-bearing. Scopes are decided first, because
 * every later stage may only see scopes that were actually granted; claim rules
 * then run in order, with later rules overwriting earlier ones; scope mappings
 * append into array claims; context rules fill the token response body.
 *
 * A `match` or `forEachScope` expression that is not a resource pattern is
 * compared for exact equality against the scope's canonical string form. That is
 * how non-resource scopes are handled - `match: "openid"`, `match:
 * "launch/patient"`, `match: "offline_access"` - since those can never match a
 * `{context}/{type}.{permissions}` pattern.
 *
 * @param policy - A validated policy document.
 * @param context - Everything about the authorization being decided.
 * @returns The granted scopes, the refusals, and the claims to issue.
 */
export function evaluatePolicy(
  policy: PolicyDocument,
  context: EvaluationContext,
): PolicyEvaluation {
  const patterns = new Map<string, ParsedScopePattern | undefined>();

  /** Parses a pattern once per evaluation. */
  const patternFor = (
    pattern: ScopePattern,
  ): ParsedScopePattern | undefined => {
    if (!patterns.has(pattern)) {
      patterns.set(pattern, parseScopePattern(pattern));
    }
    return patterns.get(pattern);
  };

  /** Matches a scope against an expression under the given semantics. */
  const matches = (
    expression: ScopePattern,
    scope: Scope,
    mode: MatchMode,
  ): boolean => {
    const parsed = patternFor(expression);
    if (parsed === undefined) {
      return formatScope(scope) === expression;
    }
    return mode === "within"
      ? scopeMatchesWithin(scope, parsed)
      : scopeMatchesIntersects(scope, parsed);
  };

  /** True when a grant rule's preconditions hold for this authorization. */
  const grantConditionsMet = (rule: ScopeGrantRule): boolean => {
    if (rule.requireContext !== undefined) {
      for (const key of rule.requireContext) {
        if (!hasContextValue(context.context, key)) {
          return false;
        }
      }
    }
    if (rule.requireUserRole !== undefined) {
      const user = context.user;
      if (
        user === null ||
        !rule.requireUserRole.some((role) => user.roles.includes(role))
      ) {
        return false;
      }
    }
    if (
      rule.grantTypes !== undefined &&
      !rule.grantTypes.includes(context.grantType)
    ) {
      return false;
    }
    if (
      rule.clientTypes !== undefined &&
      !rule.clientTypes.includes(context.client.type)
    ) {
      return false;
    }
    return true;
  };

  /**
   * Attempts to reduce a scope to something an opted-in rule permits.
   *
   * Only reached when no rule matched the scope outright, so an explicit
   * `allow: false` can never be narrowed around.
   */
  const attemptNarrowing = (scope: Scope): GrantDecision | undefined => {
    for (const rule of policy.scopeGrants) {
      if (rule.enabled === false || rule.narrow !== true || !rule.allow) {
        continue;
      }
      const parsed = patternFor(rule.match);
      if (parsed === undefined || !grantConditionsMet(rule)) {
        continue;
      }
      const narrowed = narrowScopeToPattern(scope, parsed);
      if (narrowed !== undefined) {
        return {
          allow: true,
          narrowedTo: narrowed,
          ...(rule.id === undefined ? {} : { ruleId: rule.id }),
        };
      }
    }
    return undefined;
  };

  /** Finds the first applicable grant rule and reports its decision. */
  const decide = (scope: Scope): GrantDecision => {
    for (const [index, rule] of policy.scopeGrants.entries()) {
      if (rule.enabled === false) {
        continue;
      }
      if (!matches(rule.match, scope, "within")) {
        continue;
      }
      if (!grantConditionsMet(rule)) {
        continue;
      }
      if (rule.allow) {
        return { allow: true };
      }
      const label = rule.id ?? `scopeGrants[${index}]`;
      return {
        allow: false,
        reason: `Denied by rule ${label} matching "${rule.match}"`,
        ...(rule.id === undefined ? {} : { ruleId: rule.id }),
      };
    }
    return (
      attemptNarrowing(scope) ?? {
        allow: false,
        reason: "No grant rule matches this scope, and the default is to deny",
      }
    );
  };

  const grantedScopes: Scope[] = [];
  const deniedScopes: DeniedScope[] = [];
  const narrowedScopes: NarrowedScope[] = [];
  const seen = new Set<string>();

  for (const scope of context.requested) {
    const key = formatScope(scope);
    // A repeated scope is decided once; the same rules would decide it the same
    // way, and duplicate authorities or duplicate refusals only add noise.
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);

    const decision = decide(scope);
    if (decision.allow) {
      if (decision.narrowedTo === undefined) {
        grantedScopes.push(scope);
      } else {
        grantedScopes.push(decision.narrowedTo);
        narrowedScopes.push({
          requested: scope,
          granted: decision.narrowedTo,
          ...(decision.ruleId === undefined ? {} : { ruleId: decision.ruleId }),
        });
      }
    } else {
      deniedScopes.push({
        scope,
        reason: decision.reason,
        ...(decision.ruleId === undefined ? {} : { ruleId: decision.ruleId }),
      });
    }
  }

  const grantedStrings = grantedScopes.map((scope) => formatScope(scope));
  const baseScope = buildTemplateScope(context, grantedStrings);

  /** True when a claim, mapping or context rule's condition holds. */
  const conditionMet = (when: RuleCondition | undefined): boolean => {
    if (when === undefined) {
      return true;
    }
    // `always` is a constraint like any other: true is a no-op, false never
    // holds, which gives an author a way to park a rule without deleting it.
    if (when.always === false) {
      return false;
    }
    const pattern = when.scope;
    if (
      pattern !== undefined &&
      !grantedScopes.some((scope) => matches(pattern, scope, "within"))
    ) {
      return false;
    }
    if (when.context !== undefined) {
      for (const key of when.context) {
        if (!hasContextValue(context.context, key)) {
          return false;
        }
      }
    }
    if (
      when.grantTypes !== undefined &&
      !when.grantTypes.includes(context.grantType)
    ) {
      return false;
    }
    if (
      when.clientTypes !== undefined &&
      !when.clientTypes.includes(context.client.type)
    ) {
      return false;
    }
    if (when.userRole !== undefined) {
      const user = context.user;
      if (
        user === null ||
        !when.userRole.some((role) => user.roles.includes(role))
      ) {
        return false;
      }
    }
    if (
      when.hasUser !== undefined &&
      when.hasUser !== (context.user !== null)
    ) {
      return false;
    }
    return true;
  };

  /** Renders an `emit` block into a target record. */
  const applyEmit = (
    target: Record<string, unknown>,
    emit: Readonly<Record<string, TemplateValue>>,
  ): void => {
    for (const [name, template] of Object.entries(emit)) {
      const value = renderTemplateValue(template, baseScope);
      // An unresolvable template drops the claim rather than emitting null, and
      // leaves any value an earlier rule set in place.
      if (value === undefined) {
        continue;
      }
      target[name] = value;
    }
  };

  const claims: Record<string, unknown> = {};
  for (const rule of policy.claimRules) {
    if (rule.enabled === false || !conditionMet(rule.when)) {
      continue;
    }
    applyEmit(claims, rule.emit);
  }

  for (const rule of policy.scopeMappings ?? []) {
    if (rule.enabled === false || !conditionMet(rule.when)) {
      continue;
    }

    const candidates: string[] = [...seedValues(claims[rule.appendTo])];

    for (const scope of grantedScopes) {
      if (!matches(rule.forEachScope, scope, "intersects")) {
        continue;
      }
      const scoped = buildTemplateScope(context, grantedStrings, scope);
      for (const template of rule.values) {
        candidates.push(...toAppendable(renderTemplate(template, scoped)));
      }
    }

    const collected = dedupe(candidates);
    // An empty result leaves the claim absent rather than emitting `[]`, which
    // some resource servers treat differently from a missing claim.
    if (collected.length > 0) {
      claims[rule.appendTo] = collected;
    }
  }

  const contextParams: Record<string, unknown> = {};
  for (const rule of policy.contextRules) {
    if (rule.enabled === false || !conditionMet(rule.when)) {
      continue;
    }
    applyEmit(contextParams, rule.emit);
  }

  return {
    grantedScopes,
    deniedScopes,
    narrowedScopes,
    claims,
    contextParams,
    accessTokenTtl: policy.defaults.accessTokenTtl,
    refreshTokenTtl: policy.defaults.refreshTokenTtl,
  };
}
