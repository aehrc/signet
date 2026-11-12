/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * What an edit to an account's email address does to its verified flag.
 *
 * `email_verified` is a claim about one address. An operator who changes or clears
 * the address has said nothing about the new one, so the flag is withdrawn unless
 * the same edit sets it again - a verified flag must originate from somebody
 * vouching for the address it is released beside, not survive from an older one.
 *
 * Author: John Grimes
 */

/** The account fields the rule reads. */
export interface EmailState {
  readonly email: string | null;
  readonly emailVerified: boolean;
}

/** The part of an edit the rule looks at; anything else passes through. */
export interface EmailEdit {
  readonly email?: string | null | undefined;
  readonly emailVerified?: boolean | undefined;
}

/**
 * Adds `emailVerified: false` to an edit that changes the address without naming the
 * flag.
 *
 * @param current - The account as it stands.
 * @param edit - The fields being changed.
 * @returns The edit, with the flag withdrawn where the address changes unvouched.
 * @example
 * withEmailVerification(
 *   { email: "jo@example.org", emailVerified: true },
 *   { email: null },
 * ); // { email: null, emailVerified: false }
 */
export function withEmailVerification<Edit extends EmailEdit>(
  current: EmailState,
  edit: Edit,
): Edit | (Edit & { readonly emailVerified: false }) {
  const changesAddress =
    edit.email !== undefined && edit.email !== current.email;
  return changesAddress && edit.emailVerified === undefined
    ? { ...edit, emailVerified: false }
    : edit;
}
