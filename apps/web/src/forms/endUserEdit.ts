/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Turning a user into a form, and a form into a request body.
 *
 * The page that uses this is a thin composition; everything here is where the
 * decisions actually are, so this is where they can be tested without a browser.
 *
 * An account belongs to the tenant, and two forms edit it: the account form, for
 * what is the same at every endpoint, and the endpoint access form, for the
 * `fhirUser` reference and a persona's default launch context, which name resources
 * on one endpoint's FHIR server and so live on the account's access to it.
 *
 * Three decisions are worth stating.
 *
 * Both APIs write only the fields a request names, so a save sends the changed ones
 * and nothing else - a form that sent everything would overwrite what another
 * operator changed while this page was open.
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

import type {
  EndpointAccessView,
  EndpointView,
  EndUserView,
} from "../api/types.js";

/** The flat, all-text shape the account edit form holds. */
export interface EndUserFormValues {
  readonly displayName: string;
  readonly email: string;
  readonly emailVerified: boolean;
  /** Roles, one per line. */
  readonly roles: string;
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
  values: EndpointAccessFormValues,
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
 * Reads a user's current values into the account form.
 *
 * @param user - The user as the API returns them.
 * @returns The values the form renders when nothing has been edited.
 */
export function endUserFormValues(user: EndUserView): EndUserFormValues {
  return {
    displayName: user.displayName,
    email: user.email ?? "",
    emailVerified: user.emailVerified,
    roles: formatList(user.roles),
    patients: formatList(attributeStringList(user.attributes, "patients")),
    encounters: formatList(attributeStringList(user.attributes, "encounters")),
  };
}

/**
 * Builds the account PATCH body for a set of edits.
 *
 * Carries only what differs from what was loaded, so a save with no changes produces
 * an empty object and sends nothing. The username is absent by construction: the form
 * has no field for it, and the API would refuse one anyway. So are the per-endpoint
 * fields, which {@link endpointAccessBody} sends to the access route instead.
 *
 * @param edited - The form's current values.
 * @param current - The user as loaded.
 * @returns The patch, which may be empty.
 * @example
 * endUserPatch({ ...values, email: "" }, user); // { email: null }
 */
export function endUserPatch(
  edited: EndUserFormValues,
  current: EndUserView,
): Record<string, unknown> {
  const email = edited.email.trim();

  const patch: Record<string, unknown> = changedFields<Record<string, unknown>>(
    {
      displayName: edited.displayName,
      // Null rather than "": the API reads the first as "clear this" and refuses
      // the second, which is not a distinction the operator should have to make.
      email: email.length === 0 ? null : email,
      emailVerified: edited.emailVerified,
      roles: parseList(edited.roles),
    },
    {
      displayName: current.displayName,
      email: current.email,
      emailVerified: current.emailVerified,
      roles: [...current.roles],
    },
  );

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

/** The flat, all-text shape the add-user form holds. */
export interface EndUserCreateForm {
  readonly username: string;
  readonly displayName: string;
  /** Ignored for a persona, which has none, and for an invited account. */
  readonly password: string;
  readonly isPersona: boolean;
  /** Whether the account's holder chooses its password through an invitation link. */
  readonly invite: boolean;
  readonly email: string;
  readonly emailVerified: boolean;
  /** Roles, one per line. */
  readonly roles: string;
}

/**
 * Builds the request body for a new account in the tenant.
 *
 * A blank field is left out rather than sent empty. The account is created with
 * access to no endpoint, so nothing that belongs to an endpoint's access is sent:
 * those fields are set once access is given.
 *
 * @param form - The form's current values.
 * @returns The body to POST.
 * @example
 * endUserCreateBody({ ...form, email: "jo@example.org" }).email;
 * // "jo@example.org"
 */
export function endUserCreateBody(
  form: EndUserCreateForm,
): Record<string, unknown> {
  const email = form.email.trim();
  const roles = parseList(form.roles);

  return {
    username: form.username,
    displayName: form.displayName,
    isPersona: form.isPersona,
    // An invited account is created without a password: its holder chooses one
    // through the link.
    ...(form.isPersona || form.invite ? {} : { password: form.password }),
    ...(roles.length === 0 ? {} : { roles }),
    ...(email.length === 0 ? {} : { email, emailVerified: form.emailVerified }),
  };
}

/** The flat, all-text shape one endpoint's access form holds. */
export interface EndpointAccessFormValues {
  readonly fhirUser: string;
  readonly defaultPatient: string;
  readonly defaultEncounter: string;
  readonly intent: string;
}

/**
 * Reads an account's access to one endpoint into the access form.
 *
 * @param access - The access as the API returns it.
 * @returns The values the form renders when nothing has been edited.
 */
export function endpointAccessFormValues(
  access: EndpointAccessView,
): EndpointAccessFormValues {
  const context = access.defaultContext ?? {};
  const contextField = (name: string): string => {
    const value = context[name];
    return typeof value === "string" ? value : "";
  };

  return {
    fhirUser: access.fhirUser ?? "",
    defaultPatient: contextField("patient"),
    defaultEncounter: contextField("encounter"),
    intent: contextField("intent"),
  };
}

/**
 * Builds the PUT body that changes an account's access to one endpoint.
 *
 * Carries only what differs from what was loaded, so an unedited form produces an
 * empty object and the page sends nothing. A cleared field is sent as null, which
 * the API reads as "clear this". The default context is sent only for a persona,
 * whose launch context it seeds, and nothing at all is sent for an OAuth endpoint,
 * which refuses both fields.
 *
 * @param edited - The form's current values.
 * @param current - The access as loaded.
 * @param isPersona - Whether the account is a persona.
 * @returns The body, which may be empty.
 * @example
 * endpointAccessBody({ ...values, fhirUser: "" }, access, false);
 * // { fhirUserReference: null }
 */
export function endpointAccessBody(
  edited: EndpointAccessFormValues,
  current: EndpointAccessView,
  isPersona: boolean,
): Record<string, unknown> {
  if (current.kind !== "smart") {
    return {};
  }
  const fhirUser = edited.fhirUser.trim();
  const body: Record<string, unknown> = changedFields<Record<string, unknown>>(
    { fhirUserReference: fhirUser.length === 0 ? null : fhirUser },
    { fhirUserReference: current.fhirUser },
  );

  if (isPersona) {
    const context = defaultContextFrom(edited);
    const contextChanged =
      context === null || current.defaultContext === null
        ? context !== null || current.defaultContext !== null
        : !isSameRecord(context, current.defaultContext);
    if (contextChanged) {
      body["defaultContext"] = context;
    }
  }
  return body;
}

/** The fields of an endpoint the Endpoint access section needs. */
export type AccessEndpoint = Pick<
  EndpointView,
  "slug" | "name" | "kind" | "authMode"
>;

/** One row of the Endpoint access section: an endpoint, and the access to it. */
export interface EndpointAccessRow<Endpoint extends AccessEndpoint> {
  readonly endpoint: Endpoint;
  /** Undefined when the account has no access to the endpoint. */
  readonly access: EndpointAccessView | undefined;
}

/**
 * Pairs every endpoint of the tenant with the account's access to it.
 *
 * The tenant's list decides which rows exist and their order, so an endpoint the
 * account cannot use is still offered for giving access, and access to an endpoint
 * the list does not hold is not shown.
 *
 * @param endpoints - The tenant's endpoints, in the order to show them.
 * @param access - The account's access, as the API returns it.
 * @returns One row per endpoint.
 */
export function endpointAccessRows<Endpoint extends AccessEndpoint>(
  endpoints: readonly Endpoint[],
  access: readonly EndpointAccessView[],
): EndpointAccessRow<Endpoint>[] {
  return endpoints.map((endpoint) => ({
    endpoint,
    access: access.find((entry) => entry.slug === endpoint.slug),
  }));
}
