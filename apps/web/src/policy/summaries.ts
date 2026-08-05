/**
 * One-line rule summaries, for the collapsed cards.
 *
 * A policy of any size is unreadable as a stack of open forms, so the builder shows
 * each rule as a single line until it is expanded. That line has to be honest: a
 * summary that dropped a deny, a condition or a restriction would misrepresent the
 * policy exactly where an operator is deciding whether to look closer. A condition
 * combining fields the builder does not offer is therefore called a custom condition
 * rather than reduced to the part this code recognises.
 *
 * Author: John Grimes
 */

import type { AnyRule, RuleList } from "./rules.js";
import type {
  ClaimRule,
  ContextRule,
  RuleCondition,
  ScopeGrantRule,
  ScopeMappingRule,
} from "@signet/core";

/** The separator between a summary's fragments. */
const DOT = " · ";

/**
 * Summarises a rule in one line, for the collapsed card header.
 *
 * @param list - The list the rule belongs to, which decides its shape.
 * @param rule - The rule to summarise.
 * @returns A compact, human-readable statement of what the rule does.
 */
export function summariseRule(list: RuleList, rule: AnyRule): string {
  switch (list) {
    case "scopeGrants": {
      return summariseGrant(rule as ScopeGrantRule);
    }
    case "claimRules":
    case "contextRules": {
      return summariseEmitting(rule as ClaimRule | ContextRule);
    }
    case "scopeMappings": {
      return summariseMapping(rule as ScopeMappingRule);
    }
  }
}

/** The decision, the pattern, and every restriction the rule carries. */
function summariseGrant(rule: ScopeGrantRule): string {
  const fragments = [`${rule.allow ? "Allow" : "Deny"} ${rule.match}`];
  if (rule.narrow === true) {
    fragments.push("narrows");
  }
  if (rule.requireContext !== undefined) {
    fragments.push(`needs ${rule.requireContext.join(", ")}`);
  }
  if (rule.grantTypes !== undefined) {
    fragments.push(`${rule.grantTypes.join(", ")} only`);
  }
  if (rule.clientTypes !== undefined) {
    fragments.push(`${rule.clientTypes.join(", ")} only`);
  }
  if (rule.requireUserRole !== undefined) {
    fragments.push(`role ${rule.requireUserRole.join(" or ")}`);
  }
  return fragments.join(DOT);
}

/** The condition, then the claim names it emits. */
function summariseEmitting(rule: ClaimRule | ContextRule): string {
  const names = Object.keys(rule.emit);
  const emitted = names.length === 0 ? "emits nothing" : names.join(", ");
  return `${describeCondition(rule.when)} → ${emitted}`;
}

/** The pattern, the claim appended to, and how much accumulates. */
function summariseMapping(rule: ScopeMappingRule): string {
  const count = rule.values.length;
  const unit = count === 1 ? "value" : "values";
  return `${rule.forEachScope} → ${rule.appendTo} (${String(count)} ${unit})`;
}

/**
 * Describes a condition, or declines to.
 *
 * Mirrors the shapes the builder's condition select offers. A condition carrying
 * anything beyond one of those shapes is summarised as custom rather than as the
 * fragment this code happens to recognise.
 */
function describeCondition(condition: RuleCondition | undefined): string {
  if (condition === undefined) {
    return "Always";
  }
  const keys = Object.keys(condition);
  if (keys.length !== 1) {
    return "Custom condition";
  }
  if (condition.always === true) {
    return "Always";
  }
  if (condition.hasUser !== undefined) {
    return condition.hasUser ? "When there is a user" : "When there is no user";
  }
  if (condition.scope !== undefined) {
    return `When a scope matches ${condition.scope}`;
  }
  if (condition.context !== undefined) {
    return `When context has ${condition.context.join(", ")}`;
  }
  return "Custom condition";
}
