/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Editing the rule lists.
 *
 * All pure: a function from a document to a document. The builder's cards call these
 * and nothing else, which is why the builder contains no reasoning about ordering - and
 * ordering is the part that matters, because every list here is evaluated in order and
 * a rule moved one place can change what a token carries.
 *
 * Every rule the builder creates is given an identifier. The document type makes `id`
 * optional, because a policy written by hand or shipped as a preset may omit it, but a
 * rule with no identity cannot be reordered or edited without ambiguity - two identical
 * rules would be indistinguishable. So the editor assigns one on load and keeps it.
 *
 * Author: John Grimes
 */

import type {
  ClaimRule,
  ContextRule,
  PolicyDocument,
  ScopeGrantRule,
  ScopeMappingRule,
} from "@signet/core";

/** The lists a policy document carries, as the builder addresses them. */
export type RuleList =
  "scopeGrants" | "claimRules" | "scopeMappings" | "contextRules";

/**
 * Any rule a policy document can carry.
 *
 * A union rather than a shared "has an id" interface, so that appending a grant rule
 * where a claim rule belongs is a compile error rather than something the server
 * refuses later.
 */
export type AnyRule =
  ScopeGrantRule | ClaimRule | ScopeMappingRule | ContextRule;

/** How many random characters a generated identifier carries. */
const ID_ENTROPY = 6;

/**
 * Generates a rule identifier.
 *
 * Prefixed with the list it belongs to, so an identifier read in a diff or an audit
 * event says what kind of rule it was without looking it up.
 *
 * @param list - The list the rule belongs to.
 * @param taken - Identifiers already in use, so a generated one cannot collide.
 */
export function generateRuleId(
  list: RuleList,
  taken: ReadonlySet<string>,
): string {
  const prefix = list.replace(/s$/, "");
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const suffix = Math.random()
      .toString(36)
      .slice(2, 2 + ID_ENTROPY);
    const candidate = `${prefix}-${suffix}`;
    if (!taken.has(candidate)) {
      return candidate;
    }
  }
  // Unreachable in practice; a deterministic fallback beats an infinite loop.
  return `${prefix}-${String(taken.size + 1)}`;
}

/** Every identifier a document already uses, across all four lists. */
export function usedRuleIds(document: PolicyDocument): Set<string> {
  const ids = new Set<string>();
  for (const rule of [
    ...document.scopeGrants,
    ...document.claimRules,
    ...(document.scopeMappings ?? []),
    ...document.contextRules,
  ] as readonly AnyRule[]) {
    if (rule.id !== undefined) {
      ids.add(rule.id);
    }
  }
  return ids;
}

/** Reads a list from a document, treating an absent `scopeMappings` as empty. */
export function rulesIn(
  document: PolicyDocument,
  list: RuleList,
): readonly AnyRule[] {
  switch (list) {
    case "scopeGrants": {
      return document.scopeGrants;
    }
    case "claimRules": {
      return document.claimRules;
    }
    case "scopeMappings": {
      return document.scopeMappings ?? [];
    }
    case "contextRules": {
      return document.contextRules;
    }
  }
}

/**
 * Replaces one list, leaving the rest of the document alone.
 *
 * `scopeMappings` is dropped from the document when it becomes empty rather than being
 * stored as `[]`. The field is optional, and a policy that never maps scopes should not
 * carry an empty list that the code view then shows as something to wonder about.
 */
function withList(
  document: PolicyDocument,
  list: RuleList,
  rules: readonly AnyRule[],
): PolicyDocument {
  switch (list) {
    case "scopeGrants": {
      return { ...document, scopeGrants: rules as readonly ScopeGrantRule[] };
    }
    case "claimRules": {
      return { ...document, claimRules: rules as readonly ClaimRule[] };
    }
    case "scopeMappings": {
      if (rules.length === 0) {
        const { scopeMappings: _dropped, ...rest } = document;
        return rest;
      }
      return {
        ...document,
        scopeMappings: rules as readonly ScopeMappingRule[],
      };
    }
    case "contextRules": {
      return { ...document, contextRules: rules as readonly ContextRule[] };
    }
  }
}

/**
 * Gives every rule an identifier, leaving the ones that have one alone.
 *
 * Run when a document is loaded, so the builder can address rules from that point on.
 * A preset or a hand-written policy is the case this exists for.
 *
 * @param document - The document as loaded.
 */
export function withRuleIds(document: PolicyDocument): PolicyDocument {
  const taken = usedRuleIds(document);
  let result = document;

  for (const list of [
    "scopeGrants",
    "claimRules",
    "scopeMappings",
    "contextRules",
  ] as const) {
    const rules = rulesIn(result, list);
    if (rules.every((rule) => rule.id !== undefined)) {
      continue;
    }
    const identified = rules.map((rule) => {
      if (rule.id !== undefined) {
        return rule;
      }
      const id = generateRuleId(list, taken);
      taken.add(id);
      return { ...rule, id };
    });
    result = withList(result, list, identified);
  }
  return result;
}

/**
 * Moves a rule one place within its list.
 *
 * Out-of-range moves are no-ops rather than errors: the builder disables the button at
 * either end, and a click that raced the render should do nothing rather than throw.
 *
 * @param document - The document to edit.
 * @param list - Which list the rule is in.
 * @param id - The rule to move.
 * @param direction - `-1` to move earlier, `1` to move later.
 */
export function moveRule(
  document: PolicyDocument,
  list: RuleList,
  id: string,
  direction: -1 | 1,
): PolicyDocument {
  const rules = [...rulesIn(document, list)];
  const index = rules.findIndex((rule) => rule.id === id);
  const target = index + direction;
  if (index === -1 || target < 0 || target >= rules.length) {
    return document;
  }

  const moved = rules[index];
  const displaced = rules[target];
  if (moved === undefined || displaced === undefined) {
    return document;
  }
  rules[index] = displaced;
  rules[target] = moved;
  return withList(document, list, rules);
}

/**
 * Replaces one rule with an edited copy.
 *
 * @param document - The document to edit.
 * @param list - Which list the rule is in.
 * @param id - The rule to replace.
 * @param rule - Its replacement.
 */
export function replaceRule(
  document: PolicyDocument,
  list: RuleList,
  id: string,
  rule: AnyRule,
): PolicyDocument {
  const rules = rulesIn(document, list).map((existing) =>
    existing.id === id ? rule : existing,
  );
  return withList(document, list, rules);
}

/** Removes a rule. */
export function removeRule(
  document: PolicyDocument,
  list: RuleList,
  id: string,
): PolicyDocument {
  return withList(
    document,
    list,
    rulesIn(document, list).filter((rule) => rule.id !== id),
  );
}

/**
 * Enables or disables a rule.
 *
 * A disabled rule is kept in the document and skipped by the evaluator, which is what
 * makes "turn this off and see what changes" a thing an operator can do without
 * deleting their work - and what lets a preset ship a rule that is deliberately off,
 * as the Pathling preset does for bulk import.
 */
export function setRuleEnabled(
  document: PolicyDocument,
  list: RuleList,
  id: string,
  enabled: boolean,
): PolicyDocument {
  const rules = rulesIn(document, list).map((rule): AnyRule => {
    if (rule.id !== id) {
      return rule;
    }
    // Enabled is the default, so being enabled is expressed by having no flag
    // rather than by `enabled: true` - which keeps the code view free of noise.
    // The rest object is cast because a rest over a union loses the discriminating
    // fields' types, not because anything has been removed but `enabled`.
    if (enabled) {
      const { enabled: _dropped, ...rest } = rule;
      return rest;
    }
    return { ...rule, enabled: false };
  });
  return withList(document, list, rules);
}

/** Appends a rule, giving it an identifier. */
export function appendRule(
  document: PolicyDocument,
  list: RuleList,
  rule: AnyRule,
): PolicyDocument {
  const id = rule.id ?? generateRuleId(list, usedRuleIds(document));
  return withList(document, list, [
    ...rulesIn(document, list),
    { ...rule, id },
  ]);
}

/**
 * Applies a patch to a rule, removing the fields whose new value is nothing.
 *
 * The document's optional fields mean "absent", not "present and empty": a grant rule
 * with `grantTypes: undefined` applies to every grant type, and one with
 * `grantTypes: []` applies to none. The builder's controls produce the first when a list
 * is emptied, so this is where the key is dropped rather than set - which is also what
 * keeps the code view free of `"requireUserRole": null`.
 *
 * @param rule - The rule as it is.
 * @param changes - The fields to set, or to remove by passing undefined.
 */
export function withFields(
  rule: AnyRule,
  changes: Readonly<Record<string, unknown>>,
): AnyRule {
  const next: Record<string, unknown> = { ...rule };
  for (const [field, value] of Object.entries(changes)) {
    if (value === undefined) {
      delete next[field];
    } else {
      next[field] = value;
    }
  }
  return next as unknown as AnyRule;
}

/** Whether a rule is enabled: absent means yes. */
export function isRuleEnabled(rule: AnyRule): boolean {
  return rule.enabled !== false;
}
