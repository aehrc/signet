/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Endpoint configuration as the admin API accepts it.
 *
 * Every capability flag is listed explicitly rather than derived from the
 * database schema. The list is a conformance claim - each flag becomes an entry in
 * `.well-known/smart-configuration` - so adding a column should require a
 * deliberate decision to expose it, not inherit one. A flag missing from here is
 * simply not settable over the API, which is a safe default; a flag inherited
 * automatically would be advertised the moment it was added.
 *
 * Author: John Grimes
 */

import { z } from "zod";

import { audienceSchema, slugSchema } from "../primitives.js";

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
  supportsBackendServices: z.boolean().optional(),
  supportsDynamicRegistration: z.boolean().optional(),
});

/**
 * What an endpoint secures, fixed at creation.
 *
 * `smart` is a SMART App Launch issuer in front of a FHIR server. `oauth` is a
 * plain OAuth 2.0 / OpenID Connect issuer for any other web app or API: opaque
 * scopes, an optional `aud` at `/authorize`, and none of the SMART launch
 * machinery. Immutable because the kind decides how every stored scope, policy
 * and client registration on the endpoint is read.
 */
export const endpointKindSchema = z.enum(["smart", "oauth"]);

/** How end users authenticate on an endpoint. */
export const endpointAuthModeSchema = z.enum(["local", "persona", "oidc"]);

/** Whether consent is asked for every time, remembered, or skipped. */
export const endpointConsentModeSchema = z.enum(["always", "remember", "auto"]);

/** Token lifetimes and the operational switches that are not capabilities. */
const endpointSettingsSchema = z.object({
  name: z.string().min(1).max(200),
  description: z.string().max(2000).nullish(),
  audience: audienceSchema,
  scopesSupported: z.array(z.string().max(256)).max(200).optional(),
  userAccessBrandBundle: z.string().url().max(2048).nullish(),
  userAccessBrandIdentifier: z.string().max(256).nullish(),
  /**
   * Plain text shown on the end-user sign-in page, such as who to contact for an
   * account. Trimmed, and a message of only whitespace is stored as none, so the
   * page never shows an empty box.
   */
  loginMessage: z
    .string()
    .trim()
    .max(1000)
    .transform((message) => (message.length === 0 ? null : message))
    .nullish(),
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

/**
 * Creating an endpoint. The slug and kind are fixed at creation; see the patch
 * schema.
 */
export const endpointCreateSchema = endpointSettingsSchema
  .extend({ slug: slugSchema, kind: endpointKindSchema })
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
  .extend({
    status: z.enum(["active", "disabled"]).optional(),
    /** Refused rather than ignored: the kind cannot change after creation. */
    kind: z
      .never({ error: "An endpoint's kind is fixed at creation" })
      .optional(),
  });

/** Generating a signing key. */
export const endpointKeyCreateSchema = z.object({
  /**
   * `RS256` is accepted as well as the two SMART names, for a resource server
   * whose decoder takes nothing else. See `apps/server/src/keys/algorithms.ts`
   * for when that is the right answer and why it is not the default.
   */
  algorithm: z.enum(["RS384", "ES384", "RS256"]),
});

export type EndpointCreate = z.infer<typeof endpointCreateSchema>;
export type EndpointKind = z.infer<typeof endpointKindSchema>;
export type EndpointPatch = z.infer<typeof endpointPatchSchema>;
export type EndpointCapabilities = z.infer<typeof endpointCapabilitiesSchema>;
export type EndpointKeyCreate = z.infer<typeof endpointKeyCreateSchema>;
