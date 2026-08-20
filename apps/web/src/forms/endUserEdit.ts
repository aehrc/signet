/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Turning a user into a form, and a form into a patch.
 *
 * The page that uses this is a thin composition; everything here is where the
 * decisions actually are, so this is where they can be tested without a browser.
 *
 * Three of those decisions are worth stating.
 *
 * The API's PATCH writes only the fields a request names, so a save sends the
 * changed ones and nothing else - a form that sent everything would overwrite what
 * another operator changed while this page was open.
 *
 * A blank is not the same as an absence. A cleared `fhirUser` field means "remove the
 * reference", which the API takes as an explicit `null`, and a default context whose
 * three fields are all blank means "clear it" rather than "store an empty one" -
 * because a stored context is read back as a launch context where presence is itself
 * the signal. A field nobody touched must not appear in the body at all.
 *
 * The attributes record is replaced wholesale by the PATCH, and this form gives UI to
 * only two of its keys. So the merge happens here: `patients` and `encounters` are
 * replaced, an emptied one is removed, and every other key is copied through
 * untouched. Getting that wrong would silently delete configuration this page never
 * showed anybody.
 *
 * Author: John Grimes
 */

import { attributeStringList } from "@signet/core";

import { changedFields, formatList, parseList } from "./lists.js";

import type { EndUserView } from "../api/types.js";

/** The flat, all-text shape the user edit form holds. */
export interface EndUserFormValues {
  readonly displayName: string;
  readonly fhirUser: string;
  /** Roles, one per line. */
  readonly roles: string;
  readonly defaultPatient: string;
  readonly defaultEncounter: string;
  readonly intent: string;
  /** Candidate patient identifiers, one per line. */
  readonly patients: string;
  /** Candidate encounter identifiers, one per line. */
  readonly encounters: string;
}

/**
 * Builds the attributes record to send, preserving the keys this form does not show.
 *
 * @param existing - The record as loaded.
 * @param patients - The candidate patient identifiers, as edited.
 * @param encounters - The candidate encounter identifiers, as edited.
 * @returns A new record; the argument is not modified.
 * @example
 * mergeCandidateLists({ team: "renal", patients: ["p1"] }, ["p2"], []);
 * // { team: "renal", patients: ["p2"] }
 */
export function mergeCandidateLists(
  existing: Readonly<Record<string, unknown>>,
  patients: readonly string[],
  encounters: readonly string[],
): Record<string, unknown> {
  const merged: Record<string, unknown> = { ...existing };
  const edited: readonly (readonly [string, readonly string[]])[] = [
    ["patients", patients],
    ["encounters", encounters],
  ];

  for (const [key, list] of edited) {
    if (list.length === 0) {
      // Removed rather than stored empty: the server reads a missing key and an
      // empty list identically, and the smaller record is the honest one.
      delete merged[key];
    } else {
      merged[key] = [...list];
    }
  }
  return merged;
}

/**
 * Builds the default launch context to send, or null to clear it.
 *
 * @param values - The form's three context fields.
 * @returns An object of the non-blank fields, or null when all three are blank.
 */
function defaultContextFrom(
  values: EndUserFormValues,
): Record<string, string> | null {
  const context: Record<string, string> = {};
  const fields: readonly [string, string][] = [
    ["patient", values.defaultPatient],
    ["encounter", values.defaultEncounter],
    ["intent", values.intent],
  ];
  for (const [name, value] of fields) {
    const trimmed = value.trim();
    if (trimmed.length > 0) {
      context[name] = trimmed;
    }
  }
  return Object.keys(context).length === 0 ? null : context;
}

/**
 * Whether two records hold the same keys with the same values.
 *
 * Built on {@link changedFields}, which compares arrays element-wise but only sees
 * the keys of its first argument - so a key present in one record and absent from
 * the other is caught by the count rather than by the comparison.
 *
 * @param next - The record as it would be sent.
 * @param current - The record as loaded.
 */
function isSameRecord(
  next: Readonly<Record<string, unknown>>,
  current: Readonly<Record<string, unknown>>,
): boolean {
  return (
    Object.keys(next).length === Object.keys(current).length &&
    Object.keys(changedFields(next, current)).length === 0
  );
}

/**
 * Reads a user's current values into the form.
 *
 * @param user - The user as the API returns them.
 * @returns The values the form renders when nothing has been edited.
 */
export function endUserFormValues(user: EndUserView): EndUserFormValues {
  const context = user.defaultContext ?? {};
  const contextField = (name: string): string => {
    const value = context[name];
    return typeof value === "string" ? value : "";
  };

  return {
    displayName: user.displayName,
    fhirUser: user.fhirUser ?? "",
    roles: formatList(user.roles),
    defaultPatient: contextField("patient"),
    defaultEncounter: contextField("encounter"),
    intent: contextField("intent"),
    patients: formatList(attributeStringList(user.attributes, "patients")),
    encounters: formatList(attributeStringList(user.attributes, "encounters")),
  };
}

/**
 * Builds the PATCH body for a set of edits.
 *
 * Carries only what differs from what was loaded, so a save with no changes produces
 * an empty object and sends nothing. The username is absent by construction: the form
 * has no field for it, and the API would refuse one anyway.
 *
 * @param edited - The form's current values.
 * @param current - The user as loaded.
 * @returns The patch, which may be empty.
 * @example
 * endUserPatch({ ...values, fhirUser: "" }, user); // { fhirUserReference: null }
 */
export function endUserPatch(
  edited: EndUserFormValues,
  current: EndUserView,
): Record<string, unknown> {
  const fhirUser = edited.fhirUser.trim();

  const patch: Record<string, unknown> = changedFields<Record<string, unknown>>(
    {
      displayName: edited.displayName,
      // Null rather than "": the API reads the first as "clear this" and refuses
      // the second, which is not a distinction the operator should have to make.
      fhirUserReference: fhirUser.length === 0 ? null : fhirUser,
      roles: parseList(edited.roles),
    },
    {
      displayName: current.displayName,
      fhirUserReference: current.fhirUser,
      roles: [...current.roles],
    },
  );

  const context = defaultContextFrom(edited);
  const contextChanged =
    context === null || current.defaultContext === null
      ? context !== null || current.defaultContext !== null
      : !isSameRecord(context, current.defaultContext);
  if (contextChanged) {
    patch["defaultContext"] = context;
  }

  const attributes = mergeCandidateLists(
    current.attributes,
    parseList(edited.patients),
    parseList(edited.encounters),
  );
  if (!isSameRecord(attributes, current.attributes)) {
    patch["attributes"] = attributes;
  }

  return patch;
}
