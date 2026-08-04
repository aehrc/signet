/**
 * Saying what a scope means, in words a patient can read.
 *
 * The consent screen is the one place in Signet where the audience is not a developer or
 * an operator. `patient/Observation.rs` is precise and says nothing to the person being
 * asked, so each scope is translated - the resource type into a phrase, the permission
 * letters into verbs, and the context into whose records are involved.
 *
 * Pure and tested, because a consent screen that described a scope wrongly would be
 * collecting agreement to something other than what is about to happen.
 *
 * The resource phrases are a partial list on purpose. There are around 150 FHIR resource
 * types and a patient-facing sentence for each would be mostly guesswork; a type that is
 * not listed falls back to its own name, which is worse than a phrase and much better
 * than a wrong phrase.
 *
 * Author: John Grimes
 */

import { parseScope } from "@signet/core";

/** How each resource type reads in a sentence. */
const RESOURCE_PHRASES: Readonly<Record<string, string>> = {
  "*": "all of your health information",
  AllergyIntolerance: "your allergies",
  CarePlan: "your care plans",
  CareTeam: "your care team",
  Condition: "your health conditions",
  Device: "devices related to your care",
  DiagnosticReport: "your test and imaging reports",
  DocumentReference: "your clinical documents",
  Encounter: "your visits and admissions",
  Goal: "your care goals",
  Immunization: "your immunisations",
  Medication: "medications",
  MedicationRequest: "your prescriptions",
  MedicationStatement: "the medications you take",
  Observation: "your test results and measurements",
  Patient: "your demographic details",
  Practitioner: "details of your practitioners",
  Procedure: "procedures you have had",
  Provenance: "the origin of your records",
  QuestionnaireResponse: "questionnaires you have completed",
  RelatedPerson: "people related to your care",
  ServiceRequest: "referrals and orders about your care",
};

/** How each non-resource scope reads. */
const NAMED_SCOPE_PHRASES: Readonly<Record<string, string>> = {
  openid: "Confirm who you are",
  fhirUser: "Know which person you are in this system",
  profile: "Know which person you are in this system",
  launch: "See the patient and visit this app was opened for",
  "launch/patient": "See which patient this app is about",
  "launch/encounter": "See which visit this app is about",
  offline_access: "Keep this access when you are not using the app",
  online_access: "Keep this access while you remain signed in",
};

/** One line on the consent screen. */
export interface ScopeDescription {
  /** The raw scope, shown to a developer alongside the sentence. */
  readonly scope: string;
  /** The sentence a person reads. */
  readonly description: string;
  /** Whether it permits changing data, which the screen marks. */
  readonly writes: boolean;
}

/** The verbs a set of permission letters amounts to. */
function verbs(permissions: readonly string[]): {
  readonly reads: boolean;
  readonly writes: boolean;
  readonly deletes: boolean;
} {
  return {
    reads: permissions.includes("r") || permissions.includes("s"),
    writes: permissions.includes("c") || permissions.includes("u"),
    deletes: permissions.includes("d"),
  };
}

/** Joins a list of phrases into English. */
function joinPhrases(phrases: readonly string[]): string {
  if (phrases.length <= 1) {
    return phrases[0] ?? "";
  }
  return `${phrases.slice(0, -1).join(", ")} and ${phrases.at(-1) ?? ""}`;
}

/**
 * Describes one scope in a sentence.
 *
 * A scope that cannot be parsed is described by its own text rather than being dropped:
 * the consent screen must not silently omit something the app asked for.
 *
 * @param raw - The scope string, as the app requested it.
 */
export function describeScope(raw: string): ScopeDescription {
  const named = NAMED_SCOPE_PHRASES[raw];
  if (named !== undefined) {
    return { scope: raw, description: named, writes: false };
  }

  const parsed = parseScope(raw);
  if (!parsed.ok || parsed.scope.kind !== "resource") {
    return {
      scope: raw,
      description: `Access described by "${raw}"`,
      writes: false,
    };
  }

  const scope = parsed.scope;
  const subject =
    RESOURCE_PHRASES[scope.resourceType] ??
    `your ${scope.resourceType} records`;
  const { reads, writes, deletes } = verbs(scope.permissions);

  const actions: string[] = [
    ...(reads ? ["read"] : []),
    ...(writes ? ["add to or change"] : []),
    ...(deletes ? ["delete"] : []),
  ];

  // A `user`-context scope is about everything the person may see, not only their own
  // record, and saying "your" would understate it.
  const scoped =
    scope.context === "user"
      ? subject.replace(/^your /, "").replace(/^all of your /, "all ")
      : subject;
  const qualifier = contextQualifier(scope.context);

  return {
    scope: raw,
    description: `${capitalise(joinPhrases(actions))} ${scoped}${qualifier}`,
    writes: writes || deletes,
  };
}

/**
 * What to add to a description so the scope's reach is not overstated.
 *
 * A patient-context scope is about one record and needs nothing; a user-context scope
 * covers everything the person may see; a system-context scope covers the server.
 *
 * @param context - The scope's context.
 */
function contextQualifier(context: string): string {
  switch (context) {
    case "user": {
      return " that you have access to";
    }
    case "system": {
      return " across the whole server";
    }
    default: {
      return "";
    }
  }
}

/** Upper-cases the first letter of a sentence. */
function capitalise(text: string): string {
  return text.length === 0
    ? text
    : `${text[0]?.toUpperCase() ?? ""}${text.slice(1)}`;
}

/**
 * Describes every scope an app asked for.
 *
 * Order is preserved, so the screen lists them as the app requested them - and the
 * scopes that permit writing are marked rather than reordered, because moving them
 * would break the correspondence with what a developer sees in their own request.
 *
 * @param scopes - The requested scopes.
 */
export function describeScopes(
  scopes: readonly string[],
): readonly ScopeDescription[] {
  return scopes.map((scope) => describeScope(scope));
}

/** Whether any of the requested scopes permits changing data. */
export function includesWrites(scopes: readonly string[]): boolean {
  return describeScopes(scopes).some((description) => description.writes);
}
