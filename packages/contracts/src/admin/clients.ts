/**
 * Client registration as the admin API accepts it.
 *
 * The three client types differ in what credential they present, and the schema
 * refuses the combinations that cannot work rather than leaving them to fail at
 * the token endpoint: a public client with a secret, an asymmetric client with no
 * keys, and a client offering both an inline JWKS and a `jwks_uri` are all
 * rejected here. The last is not merely redundant — with two key sources there is
 * no answer to "which one was the assertion verified against?".
 */

import { z } from "zod";

import { redirectUriSchema } from "../primitives.js";

/** How a client authenticates, or that it cannot. */
export const clientTypeSchema = z.enum([
  "public",
  "confidential-symmetric",
  "confidential-asymmetric",
]);

/** Grants a client may be registered for. */
export const grantTypeSchema = z.enum([
  "authorization_code",
  "client_credentials",
  "refresh_token",
]);

/** Registration lifecycle. Only `active` may obtain a token. */
export const clientStatusSchema = z.enum([
  "pending",
  "active",
  "suspended",
  "rejected",
]);

/** A JSON Web Key Set, checked only for shape; `jose` validates the keys. */
export const jwksSchema = z.object({
  keys: z.array(z.record(z.string(), z.unknown())).min(1),
});

/** The fields shared by creating and editing a client. */
const clientFieldsSchema = z.object({
  name: z.string().min(1).max(200),
  description: z.string().max(2000).nullish(),
  logoUrl: z.string().url().max(2048).nullish(),
  redirectUris: z.array(redirectUriSchema).max(20).optional(),
  launchUri: z.string().url().max(2048).nullish(),
  grantTypes: z.array(grantTypeSchema).min(1).max(3).optional(),
  allowedScopes: z.array(z.string().max(256)).max(200).optional(),
  contactEmail: z.string().max(320).nullish(),
  attributes: z.record(z.string(), z.unknown()).optional(),
  jwks: jwksSchema.nullish(),
  jwksUri: z.string().url().max(2048).nullish(),
  status: clientStatusSchema.optional(),
});

/**
 * Rejects a client whose credential arrangement cannot authenticate it.
 *
 * Applied to creation and to editing alike, which is why it is a function over
 * the parsed shape rather than a refinement written twice.
 */
function checkCredentials(
  value: {
    readonly clientType?: z.infer<typeof clientTypeSchema> | undefined;
    readonly secret?: string | null | undefined;
    readonly jwks?: unknown;
    readonly jwksUri?: string | null | undefined;
  },
  ctx: z.RefinementCtx,
): void {
  if (
    value.jwks !== undefined &&
    value.jwks !== null &&
    value.jwksUri !== undefined &&
    value.jwksUri !== null
  ) {
    ctx.addIssue({
      code: "custom",
      path: ["jwksUri"],
      message:
        "Set either an inline JWKS or a jwks_uri, not both: with two key sources there is no single answer to which key verified an assertion",
    });
  }

  if (value.clientType === "public" && typeof value.secret === "string") {
    ctx.addIssue({
      code: "custom",
      path: ["secret"],
      message:
        "A public client cannot hold a secret; it authenticates with PKCE alone",
    });
  }

  if (
    value.clientType === "confidential-asymmetric" &&
    (value.jwks === undefined || value.jwks === null) &&
    (value.jwksUri === undefined || value.jwksUri === null)
  ) {
    ctx.addIssue({
      code: "custom",
      path: ["jwks"],
      message:
        "An asymmetric client needs an inline JWKS or a jwks_uri to verify its assertions against",
    });
  }
}

/**
 * Registering a client.
 *
 * `clientId` may be supplied — a connectathon usually wants a memorable one, and
 * an app being migrated has one already — and is otherwise generated. A
 * symmetric client's secret is likewise generated unless given, and either way is
 * returned exactly once.
 */
export const clientCreateSchema = clientFieldsSchema
  .extend({
    clientId: z
      .string()
      .min(3)
      .max(128)
      .regex(/^[A-Za-z0-9._~-]+$/, {
        message:
          "Must be URL-safe: letters, digits, dot, underscore, tilde or hyphen",
      })
      .optional(),
    clientType: clientTypeSchema,
    /** Supply to adopt an existing secret; omit to have one generated. */
    secret: z.string().min(16).max(512).optional(),
    secretExpiresAt: z.coerce.date().nullish(),
  })
  .superRefine(checkCredentials);

/**
 * Editing a client.
 *
 * The type is absent: changing it would change which credential the client must
 * present, invalidating the one it holds, and the operations that replace a
 * credential are separate and separately audited.
 */
export const clientPatchSchema = clientFieldsSchema
  .partial()
  .superRefine((value, ctx) => {
    checkCredentials(value, ctx);
  });

/** Rotating a symmetric client's secret. */
export const clientSecretRotationSchema = z.object({
  /** Supply to set a known secret; omit to have one generated. */
  secret: z.string().min(16).max(512).optional(),
  secretExpiresAt: z.coerce.date().nullish(),
});

/** A developer's self-serve request for a client. */
export const clientRequestSchema = z.object({
  name: z.string().min(1).max(200),
  description: z.string().max(2000).optional(),
  logoUrl: z.string().url().max(2048).optional(),
  clientType: clientTypeSchema,
  redirectUris: z.array(redirectUriSchema).max(20),
  launchUri: z.string().url().max(2048).optional(),
  requestedScopes: z.array(z.string().max(256)).max(200),
  contactEmail: z.string().min(3).max(320),
  note: z.string().max(2000).optional(),
});

/**
 * An administrator's decision on a request.
 *
 * An approval carries the client to register, because the administrator may
 * narrow what was asked for — trimming a scope, correcting a redirect URI — and
 * the request payload is retained verbatim so the difference stays visible.
 */
export const clientRequestDecisionSchema = z.object({
  decisionNote: z.string().max(2000).optional(),
  client: clientCreateSchema.optional(),
});

export type ClientCreate = z.infer<typeof clientCreateSchema>;
export type ClientPatch = z.infer<typeof clientPatchSchema>;
export type ClientSecretRotation = z.infer<typeof clientSecretRotationSchema>;
export type ClientRequestSubmission = z.infer<typeof clientRequestSchema>;
export type ClientRequestDecision = z.infer<typeof clientRequestDecisionSchema>;
