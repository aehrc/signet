/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * What the passkey dialog says, as plain functions.
 *
 * The dialog itself is a component and holds no judgement of its own; everything
 * with a branch in it lives here, where it can be tested without a browser. That
 * matters most for the failure messages: a passkey ceremony fails in three quite
 * different ways - the person dismissed the prompt, the authenticator is already
 * registered, or the server refused - and the browser reports the first two as bare
 * `DOMException` names that mean nothing to a reader.
 *
 * Author: John Grimes
 */

import { MAX_PASSKEYS_PER_ACCOUNT } from "@signet/core";

import { describeError } from "../api/errors.js";

/** Which ceremony a failure came from, since the wording differs. */
export type Ceremony = "registration" | "sign-in";

/**
 * The count shown beneath the list.
 *
 * Against the limit rather than on its own, because the number a reader needs is
 * how much room is left before the register button stops working.
 *
 * @param count - How many passkeys the account holds.
 * @returns A caption, or a plainer sentence when there are none.
 */
export function passkeyCountLabel(count: number): string {
  return count === 0
    ? "No passkeys yet"
    : `${String(count)} of ${String(MAX_PASSKEYS_PER_ACCOUNT)} passkeys`;
}

/**
 * Why registration is unavailable, or undefined when it is not.
 *
 * A disabled control with no explanation is a dead end, so the reason is returned
 * alongside rather than left for the reader to infer from a greyed-out button.
 *
 * @param count - How many passkeys the account holds.
 */
export function registrationBlockedReason(count: number): string | undefined {
  return count >= MAX_PASSKEYS_PER_ACCOUNT
    ? `This account holds ${String(MAX_PASSKEYS_PER_ACCOUNT)} passkeys, which is the limit. Remove one before adding another.`
    : undefined;
}

/**
 * The sentence to show when a ceremony did not complete.
 *
 * Two of the browser's own failures are worth translating and the rest are not:
 *
 * - `NotAllowedError` is what a dismissed prompt and a timeout both produce, so the
 *   message says what happened rather than guessing why.
 * - `InvalidStateError` is what `excludeCredentials` produces when the chosen
 *   authenticator already holds a passkey for this account. It is the one refusal a
 *   person is likely to meet deliberately, and the raw name explains nothing.
 *
 * Anything else - including every refusal from the server, which arrives as an
 * `ApiError` carrying a message written for an operator - is passed through.
 *
 * @param error - What the ceremony or the request threw.
 * @param ceremony - Which one it was, since the wording differs.
 * @returns A sentence for the reader.
 * @example
 * ```ts
 * describeCeremonyFailure(dismissed, "registration");
 * // "Registration was not completed."
 * ```
 */
export function describeCeremonyFailure(
  error: unknown,
  ceremony: Ceremony,
): string {
  const name = error instanceof Error ? error.name : "";

  if (name === "InvalidStateError") {
    return "That authenticator already holds a passkey for this account. Use a different one, or remove the existing passkey first.";
  }
  if (name === "NotAllowedError") {
    return ceremony === "registration"
      ? "Registration was not completed."
      : "Sign-in was not completed.";
  }
  return describeError(error);
}
