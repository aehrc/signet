/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Checking a newly chosen password before it is sent.
 *
 * A courtesy, not a rule: the server applies the same bound and is what decides.
 * The check exists so that a typing slip in the confirmation is caught before the
 * single-use link is spent on a password nobody can repeat.
 *
 * Author: John Grimes
 */

import { END_USER_PASSWORD_MIN_LENGTH } from "@signet/contracts";

/** The shortest password the server accepts. */
const MINIMUM_LENGTH = END_USER_PASSWORD_MIN_LENGTH;

/** The problems with a choice, keyed by the field each belongs under. */
export interface PasswordChoiceIssues {
  readonly password?: string;
  readonly confirmation?: string;
}

/**
 * Finds what is wrong with a password and its confirmation.
 *
 * Length is counted as the server counts it, in UTF-16 code units, so the two
 * cannot disagree about a password at the boundary.
 *
 * @param password - The password chosen.
 * @param confirmation - The same password, typed again.
 * @returns The problems by field; empty when the choice can be sent.
 * @example
 * passwordChoiceIssues("short", "short");
 * // => { password: "Use at least 8 characters." }
 */
export function passwordChoiceIssues(
  password: string,
  confirmation: string,
): PasswordChoiceIssues {
  return {
    ...(password.length < MINIMUM_LENGTH
      ? { password: `Use at least ${String(MINIMUM_LENGTH)} characters.` }
      : {}),
    ...(password === confirmation
      ? {}
      : { confirmation: "The two passwords are not the same." }),
  };
}
