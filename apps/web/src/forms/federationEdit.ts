/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Turning an upstream identity provider into a form, and the form into a request.
 *
 * Two decisions are worth stating.
 *
 * The client secret is write-only. The form always starts with it blank, and a blank
 * secret is left out of the request rather than sent empty - which is the difference
 * between keeping the stored secret and clearing it.
 *
 * The identity claim mapped depends on the endpoint's kind. A SMART endpoint maps
 * the upstream claim that yields a `fhirUser` reference; an OAuth endpoint has no
 * `fhirUser`, and maps the email claim instead, which the API refuses on SMART. The
 * other kind's mapping is dropped from the request even if the form holds one, so a
 * value the page never showed cannot reach the API.
 *
 * Author: John Grimes
 */

import { parseList, withoutBlanks } from "./lists.js";

import type { IdpConfigView } from "../api/types.js";
import type { EndpointKind } from "@signet/core";

/** The federation form's fields, as text. */
export interface FederationForm {
  readonly issuer: string;
  readonly displayName: string;
  readonly clientId: string;
  readonly clientSecret: string;
  /** Space-delimited. */
  readonly scopes: string;
  readonly fhirUser: string;
  readonly email: string;
  readonly roles: string;
  readonly displayNameClaim: string;
  /** One per line. */
  readonly attributes: string;
}

/** What a new provider asks for unless somebody changes it, per kind. */
const DEFAULT_SCOPES: Readonly<Record<EndpointKind, string>> = {
  smart: "openid profile",
  // An OAuth endpoint releases `email`, so it needs the upstream claim to map.
  oauth: "openid profile email",
};

/**
 * Reads whatever is configured into the form.
 *
 * @param config - The stored provider, or null when there is none.
 * @param kind - The endpoint's kind, which decides the default scopes.
 * @returns The values the form renders when nothing has been edited.
 * @example
 * federationFormValues(null, "oauth").scopes; // "openid profile email"
 */
export function federationFormValues(
  config: IdpConfigView | null | undefined,
  kind: EndpointKind,
): FederationForm {
  return {
    issuer: config?.issuer ?? "",
    displayName: config?.displayName ?? "",
    clientId: config?.clientId ?? "",
    // Always blank: a stored secret is never sent back, and an empty field means
    // "leave it alone" rather than "clear it".
    clientSecret: "",
    scopes: config?.scopes.join(" ") ?? DEFAULT_SCOPES[kind],
    fhirUser: config?.claimMappings.fhirUser ?? "",
    email: config?.claimMappings.email ?? "",
    roles: config?.claimMappings.roles ?? "",
    displayNameClaim: config?.claimMappings.displayName ?? "",
    attributes: (config?.claimMappings.attributes ?? []).join("\n"),
  };
}

/**
 * Builds the request body that saves a provider.
 *
 * @param form - The form's current values.
 * @param kind - The endpoint's kind, which decides the identity claim mapped.
 * @returns The body to PUT.
 * @example
 * federationRequestBody({ ...form, email: "mail" }, "oauth").claimMappings;
 * // { email: "mail" }
 */
export function federationRequestBody(
  form: FederationForm,
  kind: EndpointKind,
): Record<string, unknown> {
  const attributes = parseList(form.attributes);
  return {
    issuer: form.issuer.trim(),
    displayName:
      form.displayName.trim() === "" ? null : form.displayName.trim(),
    clientId: form.clientId.trim(),
    ...(form.clientSecret === "" ? {} : { clientSecret: form.clientSecret }),
    scopes: form.scopes.split(/\s+/).filter((scope) => scope.length > 0),
    claimMappings: {
      ...withoutBlanks(
        kind === "smart" ? { fhirUser: form.fhirUser } : { email: form.email },
      ),
      ...withoutBlanks({
        roles: form.roles,
        displayName: form.displayNameClaim,
      }),
      ...(attributes.length === 0 ? {} : { attributes }),
    },
  };
}
