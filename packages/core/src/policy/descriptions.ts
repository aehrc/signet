/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * What a consent screen says about a scope it cannot phrase itself.
 *
 * An API scope on an OAuth / OpenID Connect endpoint is an opaque string - only
 * the operator knows what `orders:read` lets an app do. The operator says so in
 * the description of the grant rule naming it, and that sentence is what the end
 * user is shown. Taken from the rule that actually granted the scope, so the
 * consent screen and the token cannot describe two different decisions.
 *
 * Author: John Grimes
 */

import type { GrantingRule } from "./types.js";

/**
 * The description of the rule that granted each scope, for those that have one.
 *
 * A scope whose rule has no description, or only whitespace, is omitted so the
 * caller falls back to showing the scope itself. A refused scope never appears:
 * it has no granting rule.
 *
 * @param grantingRules - The evaluation's record of which rule granted each scope.
 * @returns Each described scope, keyed by the scope string.
 * @example
 * grantingRuleDescriptions(evaluatePolicy(policy, context).grantingRules);
 * // { "orders:read": "Read your orders." }
 */
export function grantingRuleDescriptions(
  grantingRules: readonly GrantingRule[],
): Readonly<Record<string, string>> {
  const descriptions: Record<string, string> = {};
  for (const { scope, rule } of grantingRules) {
    const description = rule.description?.trim() ?? "";
    if (description.length > 0) {
      descriptions[scope] = description;
    }
  }
  return descriptions;
}
