/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Deciding which resource server a token is for.
 *
 * An app tells the authorization server which resource server it intends to
 * call, and Signet refuses when that is not the one this endpoint fronts. The
 * check exists to stop a token minted for one resource server being obtained
 * through an authorization server belonging to another - the confused-deputy
 * problem RFC 8707 and SMART's `aud` requirement both address.
 *
 * The two kinds of endpoint differ only in whether the client must say so.
 * SMART App Launch requires `aud` at `/authorize`. A plain OAuth client usually
 * sends nothing at all, so on an OAuth endpoint every value it does send - `aud`,
 * and each RFC 8707 `resource` - must name the endpoint's audience, and naming
 * none means the endpoint's audience.
 *
 * Comparison is exact apart from a trailing slash. `https://fhir.example.org/R4`
 * and `https://fhir.example.org/R4/` name the same base URL, every client writes
 * one or the other, and rejecting on that difference would be a configuration
 * trap with no security value. Nothing else is normalised: case, default ports
 * and percent-encoding are all significant, because two URLs differing in them
 * can genuinely be two servers.
 *
 * @see https://hl7.org/fhir/smart-app-launch/app-launch.html#obtain-authorization-code
 * @see https://www.rfc-editor.org/rfc/rfc8707
 *
 * Author: John Grimes
 */

import type { EndpointKind } from "./endpointKind.js";

/** Why a requested audience was refused. */
export type AudienceRefusal = "missing" | "mismatch";

/**
 * The outcome of resolving the audience of a request.
 *
 * The accepted value is returned rather than merely approved, so that the caller
 * carries a narrowed `string` forward instead of re-asserting that the parameter
 * it just validated is present.
 */
export type AudienceResolution =
  | { readonly ok: true; readonly audience: string }
  | { readonly ok: false; readonly reason: AudienceRefusal };

/** What a request said about its audience, and where it was sent. */
export interface AudienceRequest {
  readonly kind: EndpointKind;
  /** The endpoint's configured audience. */
  readonly audience: string;
  /** The `aud` request parameter, if there was one. */
  readonly aud?: string | undefined;
  /** Every RFC 8707 `resource` parameter, in the order sent. */
  readonly resources: readonly string[];
}

/** Drops trailing slashes so the two spellings of a base URL compare equal. */
function withoutTrailingSlash(value: string): string {
  return value.replace(/\/+$/u, "");
}

/**
 * True when a presented value names the configured audience.
 *
 * @param presented - What the client sent.
 * @param audience - The endpoint's configured audience.
 */
export function namesAudience(presented: string, audience: string): boolean {
  return withoutTrailingSlash(presented) === withoutTrailingSlash(audience);
}

/**
 * Resolves the audience a request is asking for, or why it may not have it.
 *
 * On a SMART endpoint `aud` is required and `resource` is not consulted, exactly
 * as SMART App Launch specifies. On an OAuth endpoint everything sent must name
 * the endpoint's audience, and the result is always the configured value.
 *
 * @param request - The endpoint's kind and audience, and what the client sent.
 */
export function resolveAudience(request: AudienceRequest): AudienceResolution {
  const aud =
    request.aud === undefined || request.aud.length === 0
      ? undefined
      : request.aud;

  if (request.kind === "smart") {
    if (aud === undefined) {
      return { ok: false, reason: "missing" };
    }
    return namesAudience(aud, request.audience)
      ? { ok: true, audience: aud }
      : { ok: false, reason: "mismatch" };
  }

  const presented =
    aud === undefined ? request.resources : [aud, ...request.resources];
  return presented.every((value) => namesAudience(value, request.audience))
    ? { ok: true, audience: request.audience }
    : { ok: false, reason: "mismatch" };
}
