/**
 * Editing a scope pattern with pickers instead of a text field.
 *
 * A pattern is `{context|*}/{ResourceType|*}.{permissions}`, and the builder shows it
 * as three controls: a context select, a resource type field, and five permission
 * checkboxes. These functions are the conversion between that and the string the
 * document stores.
 *
 * Parsing delegates to `@signet/core`, so the builder cannot accept a pattern the
 * evaluator would reject. What it adds is the inverse: building a pattern back from the
 * pickers, with the permission letters in the one order the grammar allows. `.sr` is
 * not a valid scope - the suffix must read `cruds` - and a UI that emitted the letters
 * in click order would produce one.
 *
 * Author: John Grimes
 */

import { parseScopePattern, PERMISSION_ORDER } from "@signet/core";

import type { Permission, ScopeContext } from "@signet/core";

/** A pattern as the builder's controls hold it. */
export interface PatternDraft {
  readonly context: ScopeContext | "*";
  /** A FHIR resource type, or `*` for every type. */
  readonly resourceType: string;
  readonly permissions: readonly Permission[];
}

/** The default a newly added grant rule starts from: patient reads. */
export const DEFAULT_PATTERN: PatternDraft = {
  context: "patient",
  resourceType: "*",
  permissions: ["r", "s"],
};

/**
 * Reads a pattern into the builder's controls.
 *
 * Returns undefined when the pattern is not a resource pattern at all - `openid` and
 * `launch/patient` are matched by exact equality rather than by pattern, and a rule
 * whose `match` is one of those is shown as a plain value rather than as pickers.
 *
 * @param pattern - The `match` or `forEachScope` value from a rule.
 */
export function patternDraft(pattern: string): PatternDraft | undefined {
  const parsed = parseScopePattern(pattern);
  if (parsed === undefined) {
    return undefined;
  }
  return {
    context: parsed.context,
    resourceType: parsed.resourceType,
    permissions: parsed.permissions,
  };
}

/**
 * Builds the pattern string from the builder's controls.
 *
 * The permissions are ordered by the grammar rather than by how they were clicked, and
 * an empty selection produces `.r` rather than a suffix-less pattern: a rule matching
 * no permission matches nothing, which is a rule that silently does nothing.
 *
 * @param draft - The controls' current state.
 */
export function formatPattern(draft: PatternDraft): string {
  const ordered = PERMISSION_ORDER.filter((permission) =>
    draft.permissions.includes(permission),
  );
  const suffix = ordered.length === 0 ? "r" : ordered.join("");
  const resourceType =
    draft.resourceType.trim().length === 0 ? "*" : draft.resourceType.trim();
  return `${draft.context}/${resourceType}.${suffix}`;
}

/**
 * Adds or removes one permission.
 *
 * @param draft - The current draft.
 * @param permission - The letter that was clicked.
 * @param selected - Whether it is now selected.
 */
export function withPermission(
  draft: PatternDraft,
  permission: Permission,
  selected: boolean,
): PatternDraft {
  const permissions = selected
    ? [...draft.permissions, permission]
    : draft.permissions.filter((existing) => existing !== permission);
  return {
    ...draft,
    permissions: PERMISSION_ORDER.filter((letter) =>
      permissions.includes(letter),
    ),
  };
}

/** What each permission letter means, for the checkbox labels. */
export const PERMISSION_LABELS: Readonly<Record<Permission, string>> = {
  c: "create",
  r: "read",
  u: "update",
  d: "delete",
  s: "search",
};

/**
 * The resource types the builder offers as suggestions.
 *
 * Not exhaustive, and not meant to be: FHIR R4 has around 150 types, and a select over
 * all of them is worse than a text field with the common ones listed. The field accepts
 * anything the scope grammar does, and the datalist is a convenience.
 */
export const COMMON_RESOURCE_TYPES: readonly string[] = [
  "*",
  "AllergyIntolerance",
  "CarePlan",
  "CareTeam",
  "Condition",
  "Device",
  "DiagnosticReport",
  "DocumentReference",
  "Encounter",
  "Goal",
  "Immunization",
  "Location",
  "Medication",
  "MedicationRequest",
  "Observation",
  "Organization",
  "Patient",
  "Practitioner",
  "Procedure",
  "Provenance",
  "QuestionnaireResponse",
  "RelatedPerson",
  "ServiceRequest",
];
