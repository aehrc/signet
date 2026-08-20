/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Managing the passkeys on a console account.
 *
 * Only the halves of each request Signet itself defines are described here. The
 * ceremony payloads - what the browser produces at the end of a registration or an
 * authentication - are WebAuthn's own JSON encodings, and they are validated by
 * `@simplewebauthn/server` against the challenge it is verifying rather than by a
 * schema here. Restating their shape would be a second definition of somebody else's
 * format, and the one that mattered would still be the library's.
 *
 * So the schemas below accept the ceremony response as an opaque object and are
 * strict about everything Signet does own: the password that gates the operation,
 * and the name that goes in the list.
 *
 * Author: John Grimes
 */

import { z } from "zod";

/**
 * Confirming the current password.
 *
 * Carried by the two operations that change the passkey list - asking for
 * registration options, and removing a passkey. The password gates the irreversible
 * step in each case, and is checked before anything else happens.
 */
export const passkeyPasswordSchema = z.object({
  password: z.string().min(1).max(1024),
});

/**
 * Completing a registration ceremony.
 *
 * No password: the challenge this consumes could only have been minted by one, so a
 * second check here would ask the person to type it again for the same decision.
 *
 * The name is nullable rather than optional so a console that has nothing to send
 * can say so explicitly; either way a blank one is replaced by the default the core
 * policy picks.
 */
export const passkeyRegistrationSchema = z.object({
  name: z.string().max(64).nullable().optional(),
  /** `RegistrationResponseJSON`, as produced by `@simplewebauthn/browser`. */
  response: z.record(z.string(), z.unknown()),
});

/**
 * Completing an authentication ceremony.
 *
 * The whole body is the browser's `AuthenticationResponseJSON`. Nothing identifies
 * the account: that is the point of a discoverable credential, and asking for an
 * email first would put account enumeration back into a flow designed without it.
 */
export const passkeyAuthenticationSchema = z.record(z.string(), z.unknown());

export type PasskeyPassword = z.infer<typeof passkeyPasswordSchema>;
export type PasskeyRegistration = z.infer<typeof passkeyRegistrationSchema>;
export type PasskeyAuthentication = z.infer<typeof passkeyAuthenticationSchema>;
