/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Validation of the SMART `aud` launch parameter.
 *
 * An app must tell the authorization server which FHIR server it intends to call,
 * and Signet must refuse when that is not the FHIR server this endpoint fronts.
 * The check exists to stop a token minted for one resource server being obtained
 * through an authorization server belonging to another - the confused-deputy
 * problem RFC 8707 and SMART's `aud` requirement both address.
 *
 * Comparison is exact apart from a trailing slash. `https://fhir.example.org/R4`
 * and `https://fhir.example.org/R4/` name the same base URL, every FHIR client
 * writes one or the other, and rejecting on that difference would be a
 * configuration trap with no security value. Nothing else is normalised: case,
 * default ports and percent-encoding are all significant, because two URLs
 * differing in them can genuinely be two servers.
 *
 * @see https://hl7.org/fhir/smart-app-launch/app-launch.html#obtain-authorization-code
 *
 * Author: John Grimes
 */

/** Why an `aud` value was refused. */
export type AudienceRefusal = "missing" | "mismatch";

/**
 * The outcome of checking `aud` against the endpoint's FHIR base URL.
 *
 * The accepted value is returned rather than merely approved, so that the caller
 * carries a narrowed `string` forward instead of re-asserting that the parameter
 * it just validated is present.
 */
export type AudienceCheck =
  | { readonly ok: true; readonly audience: string }
  | { readonly ok: false; readonly reason: AudienceRefusal };

/** Drops trailing slashes so the two spellings of a base URL compare equal. */
function withoutTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

/**
 * Checks a presented `aud` against the endpoint's FHIR base URL.
 *
 * @param presented - The `aud` request parameter, if there was one.
 * @param fhirBaseUrl - The endpoint's configured FHIR base URL.
 */
export function checkAudience(
  presented: string | undefined,
  fhirBaseUrl: string,
): AudienceCheck {
  if (presented === undefined || presented.length === 0) {
    return { ok: false, reason: "missing" };
  }
  return withoutTrailingSlash(presented) === withoutTrailingSlash(fhirBaseUrl)
    ? { ok: true, audience: presented }
    : { ok: false, reason: "mismatch" };
}
