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

import { parseScope } from "@signet/core";

import { adminErrorBody, statusForAdminError } from "./errors.js";

import type { AdminErrorIssue } from "./errors.js";
import type { SignetEnvironment } from "../context.js";
import type { EndpointKind } from "@signet/core";
import type { Context } from "hono";

/** Why a SMART-only field is refused, against each field that names one. */
const NOT_ON_OAUTH = "Not available on an OAuth / OpenID Connect endpoint";

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
 * Finds what a client registration on an OAuth endpoint may not carry.
 *
 * A launch URI is where an EHR launch starts the app, and an OAuth endpoint has no
 * EHR launch. An allowlist entry must be a scope the endpoint's grammar can parse -
 * an RFC 6749 scope-token - since an entry no request could ever match is a typo
 * nobody would otherwise be told about. Clearing the launch URI is always allowed.
 *
 * @param kind - The endpoint's kind.
 * @param body - The validated create or patch body.
 * @param body.launchUri - The launch URI, if the request sets one.
 * @param body.allowedScopes - The scope allowlist, if the request sets one.
 * @returns One issue per offending field, empty on a SMART endpoint.
 */
export function oauthClientIssues(
  kind: EndpointKind,
  body: {
    readonly launchUri?: string | null | undefined;
    readonly allowedScopes?: readonly string[] | undefined;
  },
): readonly AdminErrorIssue[] {
  if (kind !== "oauth") {
    return [];
  }
  const launch =
    body.launchUri === undefined || body.launchUri === null
      ? []
      : [{ path: "launchUri", message: NOT_ON_OAUTH }];
  const scopes = (body.allowedScopes ?? []).flatMap((raw, index) => {
    const parsed = parseScope(raw, "oauth");
    return parsed.ok
      ? []
      : [{ path: `allowedScopes.${String(index)}`, message: parsed.message }];
  });
  return [...launch, ...scopes];
}

/**
 * Answers with a 400 listing each issue, or with nothing when there are none.
 *
 * @param c - The Hono request context.
 * @param message - What the refusal says as a whole.
 * @param issues - The fields refused, each with why.
 */
function refuse(
  c: Context<SignetEnvironment>,
  message: string,
  issues: readonly AdminErrorIssue[],
): Response | undefined {
  if (issues.length === 0) {
    return undefined;
  }
  return c.json(
    adminErrorBody("invalid_request", message, issues),
    statusForAdminError("invalid_request"),
  );
}

/**
 * Answers a client registration that does not fit an OAuth endpoint with a 400.
 *
 * @param c - The Hono request context.
 * @param issues - What {@link oauthClientIssues} found.
 * @returns The 400 to answer with, or undefined when there was nothing to refuse.
 */
export function refuseOauthClient(
  c: Context<SignetEnvironment>,
  issues: readonly AdminErrorIssue[],
): Response | undefined {
  return refuse(
    c,
    "This client does not fit an OAuth / OpenID Connect endpoint",
    issues,
  );
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
  return refuse(
    c,
    "These settings exist only on a SMART on FHIR endpoint",
    offending.map((path) => ({ path, message: NOT_ON_OAUTH })),
  );
}
