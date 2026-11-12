/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The refusal for SMART-only configuration on an OAuth / OpenID Connect endpoint.
 *
 * Refused rather than ignored: an operator who turns on an EHR launch, or gives a
 * user a `fhirUser` reference, on an endpoint that has neither has misunderstood
 * something, and silently storing nothing would hide it.
 *
 * Author: John Grimes
 */

import { adminErrorBody, statusForAdminError } from "./errors.js";

import type { SignetEnvironment } from "../context.js";
import type { EndpointKind } from "@signet/core";
import type { Context } from "hono";

/**
 * Names the FHIR identity and launch context fields a request sets on an OAuth
 * endpoint's user.
 *
 * Neither exists there: there is no FHIR server for a `fhirUser` reference to
 * name, and no launch for a default context to seed. Clearing either to null is
 * always allowed.
 *
 * @param kind - The endpoint's kind.
 * @param body - The validated create or patch body.
 * @param body.fhirUserReference - The FHIR resource the user is, if set.
 * @param body.defaultContext - The launch context a persona seeds, if set.
 * @returns The offending field names, empty on a SMART endpoint.
 */
export function smartOnlyUserFields(
  kind: EndpointKind,
  body: {
    readonly fhirUserReference?: string | null | undefined;
    readonly defaultContext?: unknown;
  },
): readonly string[] {
  if (kind !== "oauth") {
    return [];
  }
  return (["fhirUserReference", "defaultContext"] as const).filter(
    (field) => body[field] !== undefined && body[field] !== null,
  );
}

/**
 * Names the upstream claim mappings a request sets that only a SMART endpoint has.
 *
 * The `fhirUser` mapping fills a reference to a resource on a FHIR server, which
 * an OAuth / OpenID Connect endpoint does not front.
 *
 * @param kind - The endpoint's kind.
 * @param mappings - The validated claim mappings, if the request sent any.
 * @returns The offending field paths, empty on a SMART endpoint.
 */
export function smartOnlyClaimMappings(
  kind: EndpointKind,
  mappings: { readonly fhirUser?: string | undefined } | undefined,
): readonly string[] {
  return kind === "oauth" && mappings?.fhirUser !== undefined
    ? ["claimMappings.fhirUser"]
    : [];
}

/**
 * Answers a request naming SMART-only fields with a 400 that lists each one.
 *
 * @param c - The Hono request context.
 * @param offending - The names of the SMART-only fields the request set.
 * @returns The 400 to answer with, or undefined when nothing was offending.
 */
export function refuseSmartOnly(
  c: Context<SignetEnvironment>,
  offending: readonly string[],
): Response | undefined {
  if (offending.length === 0) {
    return undefined;
  }
  return c.json(
    {
      ...adminErrorBody(
        "invalid_request",
        "These settings exist only on a SMART on FHIR endpoint",
      ),
      issues: offending.map((path) => ({
        path,
        message: "Not available on an OAuth / OpenID Connect endpoint",
      })),
    },
    statusForAdminError("invalid_request"),
  );
}
