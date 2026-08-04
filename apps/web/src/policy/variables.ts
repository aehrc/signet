/**
 * What a template may refer to.
 *
 * The inserter beside every claim value lists these, so nobody has to remember whether
 * it is `context.patient` or `launch.patient`. The list is written out rather than
 * derived, because the evaluation context is a type rather than a value at runtime -
 * and because each entry needs a sentence saying what it holds, which a type cannot
 * carry.
 *
 * Kept beside the filters, which are the other half of the template language and are a
 * closed set the evaluator enforces.
 *
 * Author: John Grimes
 */

import { TEMPLATE_FILTER_NAMES } from "@signet/core";

/** One thing a template can interpolate. */
export interface TemplateVariable {
  /** The path as it appears inside `{{ }}`. */
  readonly path: string;
  readonly description: string;
  /** Grouped in the inserter, so the list is scannable. */
  readonly group: "user" | "client" | "context" | "endpoint" | "scopes";
}

/** Every variable an evaluation context exposes. */
export const TEMPLATE_VARIABLES: readonly TemplateVariable[] = [
  {
    path: "user.fhirUser",
    description:
      "The signed-in user as a relative FHIR reference, e.g. Practitioner/123. Absent for a backend service.",
    group: "user",
  },
  {
    path: "user.id",
    description: "Signet's own identifier for the user.",
    group: "user",
  },
  {
    path: "user.displayName",
    description: "The user's display name.",
    group: "user",
  },
  {
    path: "user.roles",
    description:
      "The roles the user holds. An array: use the join filter to render it as a string.",
    group: "user",
  },
  {
    path: "user.attributes",
    description:
      "Arbitrary attributes on the user's record. Address one by name, as user.attributes.department.",
    group: "user",
  },
  {
    path: "client.clientId",
    description: "The OAuth client identifier of the app being authorized.",
    group: "client",
  },
  {
    path: "client.name",
    description: "The app's display name.",
    group: "client",
  },
  {
    path: "client.type",
    description: "public, confidential-symmetric or confidential-asymmetric.",
    group: "client",
  },
  {
    path: "client.attributes",
    description: "Arbitrary attributes on the client's registration.",
    group: "client",
  },
  {
    path: "context.patient",
    description: "The patient in the launch context, as a bare FHIR id.",
    group: "context",
  },
  {
    path: "context.encounter",
    description: "The encounter in the launch context, as a bare FHIR id.",
    group: "context",
  },
  {
    path: "context.intent",
    description: "The intent the EHR supplied with the launch.",
    group: "context",
  },
  {
    path: "context.tenant",
    description:
      "A sub-tenant identifier the FHIR server understands, if the launch carried one.",
    group: "context",
  },
  {
    path: "context.needPatientBanner",
    description: "Whether the EHR asked the app to show a patient banner.",
    group: "context",
  },
  {
    path: "endpoint.issuer",
    description: "This endpoint's issuer URL.",
    group: "endpoint",
  },
  {
    path: "endpoint.fhirBaseUrl",
    description:
      "The FHIR server this endpoint fronts, and the audience of every token it mints.",
    group: "endpoint",
  },
  {
    path: "endpoint.slug",
    description: "This endpoint's URL segment.",
    group: "endpoint",
  },
  {
    path: "granted",
    description:
      "The scopes the policy granted, as an array. Usually rendered with the join filter.",
    group: "scopes",
  },
  {
    path: "grantType",
    description: "authorization_code, client_credentials or refresh_token.",
    group: "scopes",
  },
  {
    path: "scope.resourceType",
    description:
      "Inside a scope mapping only: the resource type of the scope being mapped.",
    group: "scopes",
  },
  {
    path: "scope.resourceTypeSuffix",
    description:
      "Inside a scope mapping only: `:Observation` for a typed scope, and empty for a wildcard - so one template covers both.",
    group: "scopes",
  },
  {
    path: "scope.context",
    description: "Inside a scope mapping only: patient, user or system.",
    group: "scopes",
  },
];

/** The filters a template may apply, from the evaluator's closed set. */
export const TEMPLATE_FILTERS: readonly string[] = TEMPLATE_FILTER_NAMES;

/**
 * Wraps a variable path as an interpolation.
 *
 * @param path - The variable's path.
 */
export function interpolation(path: string): string {
  return `{{ ${path} }}`;
}

/**
 * Inserts an interpolation into a value at a cursor position.
 *
 * Appending is not enough: a claim value is often a template with literal text around
 * the interpolation, and the inserter should put the variable where the caret is.
 *
 * @param value - The current value.
 * @param path - The variable to insert.
 * @param at - The caret position. Clamped into range.
 */
export function insertVariable(
  value: string,
  path: string,
  at: number,
): string {
  const position = Math.max(0, Math.min(at, value.length));
  return `${value.slice(0, position)}${interpolation(path)}${value.slice(position)}`;
}

/** The variables in a group, for the inserter's sections. */
export function variablesInGroup(
  group: TemplateVariable["group"],
): readonly TemplateVariable[] {
  return TEMPLATE_VARIABLES.filter((variable) => variable.group === group);
}
