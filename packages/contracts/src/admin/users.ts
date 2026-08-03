/**
 * End users and personas as the admin API accepts them.
 *
 * A persona is an account with no password, which is why the two are described by
 * one schema with a refinement rather than two: the distinction is a property of
 * the credential, and separating them would allow a persona with a password — an
 * account that is password-free in the console and not in the database.
 */

import { z } from "zod";

import { fhirIdSchema, fhirUserReferenceSchema } from "../primitives.js";

/**
 * A launch context a persona is seeded with.
 *
 * Narrower than the full `LaunchContext` the OAuth layer validates: a seeded
 * default exists so a connectathon launch works without an EHR, and the
 * structured `fhirContext` belongs to a real launch rather than to a fixture.
 */
export const personaContextSchema = z.object({
  patient: fhirIdSchema.optional(),
  encounter: fhirIdSchema.optional(),
  intent: z.string().max(128).optional(),
});

/** The fields shared by creating and editing an end user. */
const endUserFieldsSchema = z.object({
  displayName: z.string().min(1).max(200),
  fhirUserReference: fhirUserReferenceSchema.nullish(),
  roles: z.array(z.string().max(128)).max(50).optional(),
  attributes: z.record(z.string(), z.unknown()).optional(),
  defaultContext: personaContextSchema.nullish(),
});

/**
 * Creating an end user or persona.
 *
 * A password is required unless the account is a persona, and refused when it is.
 * Personas are only *selectable* on a non-production endpoint, which the server
 * enforces at sign-in; creating one on a production endpoint is allowed so that an
 * endpoint can be seeded before it is promoted.
 */
export const endUserCreateSchema = endUserFieldsSchema
  .extend({
    username: z.string().min(1).max(128),
    password: z.string().min(8).max(1024).optional(),
    isPersona: z.boolean().optional(),
  })
  .superRefine((value, ctx) => {
    if (value.isPersona === true && value.password !== undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["password"],
        message:
          "A persona has no password: it is selected from a picker, not signed into",
      });
    }
    if (value.isPersona !== true && value.password === undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["password"],
        message:
          "A local account needs a password, or must be marked a persona",
      });
    }
  });

/**
 * Editing an end user.
 *
 * The username is absent, because it is what a stored consent and an audit trail
 * name the person by. The password is absent too: replacing a credential is a
 * separate operation with its own audit event.
 */
export const endUserPatchSchema = endUserFieldsSchema
  .partial()
  .extend({ disabled: z.boolean().optional() });

/** Setting an end user's password. */
export const endUserPasswordSchema = z.object({
  password: z.string().min(8).max(1024),
});

export type EndUserCreate = z.infer<typeof endUserCreateSchema>;
export type EndUserPatch = z.infer<typeof endUserPatchSchema>;
export type EndUserPassword = z.infer<typeof endUserPasswordSchema>;
export type PersonaContext = z.infer<typeof personaContextSchema>;
