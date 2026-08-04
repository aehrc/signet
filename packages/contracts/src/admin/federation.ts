/**
 * The upstream identity provider, as the admin API accepts it.
 *
 * The client secret is write-only across this boundary, in both directions: a
 * request may set it, and no response ever returns it. That is not a courtesy -
 * it is the difference between a console session and a credential that
 * impersonates the whole deployment to somebody else's identity provider.
 *
 * Two absences are deliberate. There is no discovery URL, only an issuer: the
 * document lives at a well-known path beneath it, and accepting both would let an
 * operator point them at different providers without noticing. And there is no
 * redirect URI, because it is derived from the endpoint's own issuer - a
 * configurable one would be a field an operator has to keep in step with a value
 * Signet already knows.
 *
 * Author: John Grimes
 */

import { z } from "zod";

/**
 * Which upstream claims populate which Signet fields.
 *
 * Every value is a claim name, and every one is optional: a provider that sends
 * nothing but `sub` still federates, it just produces an account with no FHIR
 * identity and no roles - which is an honest representation of what it told us.
 */
export const idpClaimMappingsSchema = z.object({
  /** Claim yielding a relative FHIR reference, e.g. `Practitioner/123`. */
  fhirUser: z.string().min(1).max(128).optional(),
  /** Claim yielding roles, as an array or a space-delimited string. */
  roles: z.string().min(1).max(128).optional(),
  displayName: z.string().min(1).max(128).optional(),
  /** Further claims copied verbatim into the user's attributes. */
  attributes: z.array(z.string().min(1).max(128)).max(50).optional(),
});

/** The upstream provider configuration, as written. */
export const idpConfigWriteSchema = z.object({
  /**
   * The provider's issuer identifier, compared exactly against its discovery
   * document. A trailing slash is stripped, because the two forms are different
   * issuers and an operator pasting one from a browser's address bar should not
   * have to know that.
   */
  issuer: z
    .string()
    .url()
    .max(2048)
    .transform((value) => value.replace(/\/$/, "")),
  /** What the sign-in button calls the provider. */
  displayName: z.string().max(200).nullish(),
  clientId: z.string().min(1).max(256),
  /**
   * The secret Signet presents upstream, or null for a public client.
   *
   * Omitting the field leaves any stored secret alone, which is what lets an
   * operator edit the claim mapping without re-entering a credential they may not
   * have. Sending null clears it deliberately.
   */
  clientSecret: z.string().min(1).max(2048).nullish(),
  /**
   * The scopes requested upstream. `openid` is added when it is missing, since a
   * flow without it produces no ID token and therefore no identity at all.
   */
  scopes: z.array(z.string().min(1).max(128)).max(50).optional(),
  claimMappings: idpClaimMappingsSchema.optional(),
});

/** What an operator's provider configuration looks like on the wire. */
export type IdpConfigWrite = z.infer<typeof idpConfigWriteSchema>;
