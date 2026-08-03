/**
 * The launch context, as an API caller supplies one.
 *
 * Narrower than the `LaunchContext` the OAuth layer validates, and deliberately so:
 * `fhirContext` carries nested structure with rules of its own (`reference` versus
 * `canonical` versus `identifier`, and what `role` permits), which `@signet/core`
 * owns and validates at the point a real EHR launch is minted. What an operator
 * types into the console's simulator, or seeds a persona with, is the flat part.
 *
 * One schema serves both the policy simulator and the launch simulator, because
 * they are the same question asked at two moments — "what would this context
 * produce?" and "make a handle carrying this context" — and two descriptions of it
 * would drift into a simulation that cannot be launched.
 */

import { z } from "zod";

import { fhirIdSchema } from "./primitives.js";

/** The flat launch context fields, all optional. */
export const launchContextInputSchema = z.object({
  patient: fhirIdSchema.optional(),
  encounter: fhirIdSchema.optional(),
  /** Free text the app may use to decide which of its screens to open. */
  intent: z.string().max(128).optional(),
  /** An identifier the FHIR server understands as a sub-tenant of its own. */
  tenant: z.string().max(128).optional(),
  needPatientBanner: z.boolean().optional(),
  smartStyleUrl: z.string().url().max(2048).optional(),
});

export type LaunchContextInput = z.infer<typeof launchContextInputSchema>;
