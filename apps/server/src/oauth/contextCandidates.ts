/**
 * Which patients and encounters an end user may put into a launch context.
 *
 * A standalone launch asking for `launch/patient` has to get a patient from
 * somewhere, and Signet deliberately does not get it by querying the FHIR server:
 * it holds no credential for the BYO server, and a picker that searched it would
 * have to be given one - an authorization server with read access to every
 * patient record it fronts is a much larger thing to defend than one without.
 *
 * The candidates therefore come from the end user's own record, by three
 * conventions:
 *
 * 1. The user's own `fhirUser` reference, when it is a `Patient`. A patient-facing
 *    app launched by the patient is about that patient, and this is the case that
 *    must work with no configuration at all.
 * 2. A persona's `default_context`, which is what makes a connectathon endpoint
 *    usable - seed a persona with a patient and the launch simply works.
 * 3. An explicit list in the user's `attributes`, under `patients` and
 *    `encounters`. This is the general answer for a production endpoint: the
 *    operator states which patients this user may act on, from whatever system of
 *    record they already have.
 *
 * On a non-production endpoint the user may also type an identifier that is not on
 * the list, because a connectathon needs to be able to point at arbitrary test
 * data. On a production endpoint they may not: allowing it would let any
 * authenticated user mint a token scoped to any patient, which is the one thing a
 * patient picker must not permit.
 *
 * Author: John Grimes
 */

import { attributeStringList } from "@signet/core";

import type { LaunchContext } from "@signet/core";

/** The end user fields the candidate lists are derived from. */
export interface CandidateSource {
  readonly fhirUserReference: string | null;
  readonly defaultContext: LaunchContext | null;
  readonly attributes: Readonly<Record<string, unknown>>;
}

/** Which context key candidates are being collected for. */
export type ContextKey = "patient" | "encounter";

/** The `attributes` key holding the explicit list for each context key. */
const ATTRIBUTE_KEYS: Readonly<Record<ContextKey, string>> = {
  patient: "patients",
  encounter: "encounters",
};

/** FHIR resource type prefix stripped from a reference-shaped candidate. */
const RESOURCE_TYPES: Readonly<Record<ContextKey, string>> = {
  patient: "Patient",
  encounter: "Encounter",
};

/**
 * Reduces a candidate to the logical id a launch context carries.
 *
 * A launch context's `patient` is a bare id, not a reference, but an operator
 * populating `attributes.patients` will reasonably write either - so
 * `Patient/123` and `123` are accepted and both mean `123`.
 */
function toLogicalId(value: string, key: ContextKey): string | undefined {
  const prefix = `${RESOURCE_TYPES[key]}/`;
  const id = value.startsWith(prefix) ? value.slice(prefix.length) : value;
  // The same shape `fhirIdSchema` accepts. A value outside it cannot be part of a
  // valid FHIR URL, so offering it in a picker would only produce a token nothing
  // can use.
  return /^[A-Za-z0-9\-.]{1,64}$/.test(id) ? id : undefined;
}

/**
 * Collects the identifiers a user may select for a context key.
 *
 * Deduplicated, and in a stable order: the user's own record first, then their
 * default context, then their configured list. The order is what a picker renders,
 * and the most likely choice should be first.
 *
 * @param source - The end user's record.
 * @param key - `patient` or `encounter`.
 */
export function contextCandidates(
  source: CandidateSource,
  key: ContextKey,
): readonly string[] {
  const raw: string[] = [];

  if (
    key === "patient" &&
    source.fhirUserReference !== null &&
    source.fhirUserReference.startsWith("Patient/")
  ) {
    raw.push(source.fhirUserReference);
  }

  const fromDefault = source.defaultContext?.[key];
  if (typeof fromDefault === "string") {
    raw.push(fromDefault);
  }

  raw.push(...attributeStringList(source.attributes, ATTRIBUTE_KEYS[key]));

  const seen = new Set<string>();
  const candidates: string[] = [];
  for (const value of raw) {
    const id = toLogicalId(value, key);
    if (id !== undefined && !seen.has(id)) {
      seen.add(id);
      candidates.push(id);
    }
  }
  return candidates;
}

/**
 * The candidate to resolve without asking, when there is exactly one.
 *
 * Showing a picker with a single option is a click that conveys no decision, and
 * for a patient-facing app launched by the patient it would be a click that asks
 * the user to confirm they are themselves.
 */
export function soleCandidate(
  candidates: readonly string[],
): string | undefined {
  return candidates.length === 1 ? candidates[0] : undefined;
}

/**
 * Whether a user may put a particular identifier into context.
 *
 * @param candidates - What {@link contextCandidates} offered.
 * @param requested - What the picker submitted.
 * @param allowFreeSelection - True only for a non-production endpoint. See the
 *   module header for why this is not a convenience.
 */
export function isSelectableContextValue(
  candidates: readonly string[],
  requested: string,
  allowFreeSelection: boolean,
): boolean {
  if (requested.length === 0) {
    return false;
  }
  if (candidates.includes(requested)) {
    return true;
  }
  return allowFreeSelection && /^[A-Za-z0-9\-.]{1,64}$/.test(requested);
}
