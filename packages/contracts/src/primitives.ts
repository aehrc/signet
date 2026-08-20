/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { z } from "zod";

/**
 * A URL-safe slug used in tenant and endpoint paths.
 *
 * Endpoint issuers are built from these (`/t/{tenant}/e/{endpoint}`), so they
 * must be stable, lower case and free of characters needing escaping.
 */
export const slugSchema = z
  .string()
  .min(2)
  .max(64)
  .regex(/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/, {
    message: "Must be lower-case alphanumeric with internal hyphens",
  });

/** A FHIR base URL. Must be absolute; used as the expected token `aud`. */
export const fhirBaseUrlSchema = z.string().url().max(2048);

/**
 * A `fhirUser` reference: a relative FHIR reference to the resource
 * representing an authenticated user.
 *
 * @see https://hl7.org/fhir/smart-app-launch/scopes-and-launch-context.html
 */
export const fhirUserReferenceSchema = z
  .string()
  .regex(
    /^(Patient|Practitioner|PractitionerRole|RelatedPerson|Person)\/[A-Za-z0-9\-.]{1,64}$/,
    {
      message:
        "Must be a relative reference to a Patient, Practitioner, PractitionerRole, RelatedPerson or Person",
    },
  );

/** A FHIR logical id, as used for launch context patient and encounter values. */
export const fhirIdSchema = z.string().regex(/^[A-Za-z0-9\-.]{1,64}$/);

/** A space-delimited OAuth scope parameter value. */
export const scopeStringSchema = z.string().max(8192);

/** An OAuth redirect URI. Matched exactly at the authorize endpoint. */
export const redirectUriSchema = z.string().url().max(2048);

export type Slug = z.infer<typeof slugSchema>;
export type FhirUserReference = z.infer<typeof fhirUserReferenceSchema>;
