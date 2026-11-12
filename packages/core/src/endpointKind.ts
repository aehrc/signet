/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * What an endpoint secures, fixed when it is created.
 *
 * `smart` is a SMART App Launch issuer in front of a FHIR server: SMART scope
 * grammar, launch context, `aud` required at `/authorize`. `oauth` is a plain
 * OAuth 2.0 / OpenID Connect issuer for any other web app or API: every scope
 * other than the OpenID Connect ones is an opaque string, the audience may be
 * left implicit, and none of the SMART launch machinery exists.
 *
 * Author: John Grimes
 */

/** The two kinds of endpoint. */
export type EndpointKind = "smart" | "oauth";

/**
 * The capability flags that only mean something on a SMART on FHIR endpoint.
 *
 * Each describes a launch mode, launch context, SMART scope family or SMART user
 * interface integration, none of which an OAuth / OpenID Connect endpoint has. An
 * OAuth endpoint stores them all as `false`, and setting one to `true` there is
 * refused rather than ignored, so that nothing is advertised or enabled that the
 * endpoint will never do.
 */
export const SMART_ONLY_CAPABILITY_FLAGS = [
  "supportsEhrLaunch",
  "supportsStandaloneLaunch",
  "supportsPatientBanner",
  "supportsStyling",
  "supportsEhrPatientContext",
  "supportsEhrEncounterContext",
  "supportsStandalonePatientContext",
  "supportsStandaloneEncounterContext",
  "supportsOnlineAccess",
  "supportsPatientScopes",
  "supportsUserScopes",
  "supportsV1Scopes",
  "supportsV2Scopes",
] as const;

/** One of the {@link SMART_ONLY_CAPABILITY_FLAGS}. */
export type SmartOnlyCapabilityFlag =
  (typeof SMART_ONLY_CAPABILITY_FLAGS)[number];

/**
 * Names the SMART-only settings a proposed OAuth endpoint configuration turns on.
 *
 * A flag set to `true`, or a user-access brand set to a value, is reported;
 * anything absent, `false` or `null` is not. An empty result means the
 * configuration is acceptable for an OAuth endpoint.
 *
 * @param settings - The flags and brand fields being written, as in a create or
 *   patch request.
 * @returns The names of the offending settings, in a stable order.
 */
export function smartOnlySettingsEnabled(
  settings: Readonly<
    Partial<Record<SmartOnlyCapabilityFlag, boolean | undefined>> & {
      readonly userAccessBrandBundle?: string | null | undefined;
      readonly userAccessBrandIdentifier?: string | null | undefined;
    }
  >,
): readonly string[] {
  const enabled: string[] = SMART_ONLY_CAPABILITY_FLAGS.filter(
    (flag) => settings[flag] === true,
  );
  for (const brand of [
    "userAccessBrandBundle",
    "userAccessBrandIdentifier",
  ] as const) {
    const value = settings[brand];
    if (value !== undefined && value !== null) {
      enabled.push(brand);
    }
  }
  return enabled;
}
