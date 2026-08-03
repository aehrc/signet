/**
 * Endpoint configuration as the admin API accepts it.
 *
 * Every capability flag is listed explicitly rather than derived from the
 * database schema. The list is a conformance claim — each flag becomes an entry in
 * `.well-known/smart-configuration` — so adding a column should require a
 * deliberate decision to expose it, not inherit one. A flag missing from here is
 * simply not settable over the API, which is a safe default; a flag inherited
 * automatically would be advertised the moment it was added.
 */

import { z } from "zod";

import { fhirBaseUrlSchema, slugSchema } from "../primitives.js";

/** Every capability flag, all optional so a patch can name one. */
export const endpointCapabilitiesSchema = z.object({
  supportsEhrLaunch: z.boolean().optional(),
  supportsStandaloneLaunch: z.boolean().optional(),
  supportsAuthorizePost: z.boolean().optional(),
  allowsPublicClients: z.boolean().optional(),
  allowsConfidentialSymmetricClients: z.boolean().optional(),
  allowsConfidentialAsymmetricClients: z.boolean().optional(),
  supportsOpenIdConnect: z.boolean().optional(),
  supportsPatientBanner: z.boolean().optional(),
  supportsStyling: z.boolean().optional(),
  supportsEhrPatientContext: z.boolean().optional(),
  supportsEhrEncounterContext: z.boolean().optional(),
  supportsStandalonePatientContext: z.boolean().optional(),
  supportsStandaloneEncounterContext: z.boolean().optional(),
  supportsOfflineAccess: z.boolean().optional(),
  supportsOnlineAccess: z.boolean().optional(),
  supportsPatientScopes: z.boolean().optional(),
  supportsUserScopes: z.boolean().optional(),
  supportsV1Scopes: z.boolean().optional(),
  supportsV2Scopes: z.boolean().optional(),
  supportsAppState: z.boolean().optional(),
  supportsBackendServices: z.boolean().optional(),
  supportsDynamicRegistration: z.boolean().optional(),
});

/** How end users authenticate on an endpoint. */
export const endpointAuthModeSchema = z.enum(["local", "persona", "oidc"]);

/** Whether consent is asked for every time, remembered, or skipped. */
export const endpointConsentModeSchema = z.enum(["always", "remember", "auto"]);

/** Token lifetimes and the operational switches that are not capabilities. */
const endpointSettingsSchema = z.object({
  name: z.string().min(1).max(200),
  description: z.string().max(2000).nullish(),
  fhirBaseUrl: fhirBaseUrlSchema,
  scopesSupported: z.array(z.string().max(256)).max(200).optional(),
  userAccessBrandBundle: z.string().url().max(2048).nullish(),
  userAccessBrandIdentifier: z.string().max(256).nullish(),
  /**
   * Bounded well below a day. An access token is a bearer credential a resource
   * server cannot revoke, and its lifetime is the window in which a leaked one
   * still works; SMART's own examples sit in the minutes.
   */
  accessTokenTtl: z.number().int().min(60).max(86_400).optional(),
  refreshTokenTtl: z.number().int().min(300).max(31_536_000).optional(),
  authMode: endpointAuthModeSchema.optional(),
  consentMode: endpointConsentModeSchema.optional(),
  /**
   * Personas are only selectable on a non-production endpoint, so this flag is
   * what separates a connectathon endpoint from a real one. It defaults to
   * production, and the console makes turning it off deliberate.
   */
  isProduction: z.boolean().optional(),
});

/** Creating an endpoint. The slug is fixed at creation; see the patch schema. */
export const endpointCreateSchema = endpointSettingsSchema
  .extend({ slug: slugSchema })
  .extend(endpointCapabilitiesSchema.shape);

/**
 * Editing an endpoint.
 *
 * The slug is deliberately absent. It is part of the issuer, and every token
 * already minted carries that issuer in `iss`; renaming it silently would break
 * every registered app and every FHIR server pointed at the endpoint. Moving an
 * endpoint means creating a new one.
 */
export const endpointPatchSchema = endpointSettingsSchema
  .partial()
  .extend(endpointCapabilitiesSchema.shape)
  .extend({ status: z.enum(["active", "disabled"]).optional() });

/** Generating a signing key. */
export const endpointKeyCreateSchema = z.object({
  algorithm: z.enum(["RS384", "ES384"]),
});

export type EndpointCreate = z.infer<typeof endpointCreateSchema>;
export type EndpointPatch = z.infer<typeof endpointPatchSchema>;
export type EndpointCapabilities = z.infer<typeof endpointCapabilitiesSchema>;
export type EndpointKeyCreate = z.infer<typeof endpointKeyCreateSchema>;
