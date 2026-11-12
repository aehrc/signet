/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Invitation links for an endpoint's local accounts.
 *
 * An administrator creates the account, then sends its holder a link through their
 * own mail client; opening the link lets the holder choose the account's password.
 * The same link resets a password that has been forgotten.
 *
 * The rules are here rather than in the server so that the console, which decides
 * whether to offer an invitation, and the admin API, which decides whether to mint
 * one, cannot disagree. The same applies to the link: the server writes it and the
 * invitation page reads it back, so both halves of the format live side by side.
 *
 * Author: John Grimes
 */

/** Why an account cannot be sent an invitation. */
export type InvitationRefusal =
  /** A persona has no password by design: it is chosen from a picker. */
  | "persona"
  /** The endpoint authenticates through an upstream provider, not a password. */
  | "federated"
  /** A disabled account could not sign in with the password it chose. */
  | "disabled";

/** How long an invitation link stays usable: seven days. */
export const INVITATION_TTL_SECONDS = 7 * 24 * 60 * 60;

/** What the console and the admin API say about each refusal. */
export const INVITATION_REFUSAL_MESSAGES: Readonly<
  Record<InvitationRefusal, string>
> = {
  persona:
    "A persona has no password: it is selected from a picker, not signed into",
  federated:
    "This endpoint federates authentication to an upstream identity provider, so a local password would never be checked",
  disabled:
    "This account is disabled. Enable it before sending an invitation, or it will not be able to sign in",
};

/**
 * Decides whether an account may be sent an invitation.
 *
 * Only an enabled local account on an endpoint in `local` auth mode qualifies. The
 * auth mode is matched by name, so a mode added later is refused until a rule
 * admits it.
 *
 * @param endpoint - The endpoint the account belongs to.
 * @param endpoint.authMode - The endpoint's `auth_mode`.
 * @param user - The account.
 * @param user.isPersona - Whether the account is a persona.
 * @param user.disabledAt - When the account was disabled, as a `Date` or as the
 *   ISO 8601 string the console holds, or null.
 * @returns The reason for refusing, or undefined when the account qualifies.
 * @example
 * invitationRefusal({ authMode: "local" }, { isPersona: true, disabledAt: null });
 * // => "persona"
 */
export function invitationRefusal(
  endpoint: { readonly authMode: string },
  user: {
    readonly isPersona: boolean;
    readonly disabledAt: Date | string | null;
  },
): InvitationRefusal | undefined {
  if (user.isPersona) {
    return "persona";
  }
  if (endpoint.authMode !== "local") {
    return "federated";
  }
  if (user.disabledAt !== null) {
    return "disabled";
  }
  return undefined;
}

/**
 * When an invitation issued now stops being usable.
 *
 * @param now - The moment of issue.
 * @returns The expiry instant.
 */
export function invitationExpiry(now: Date): Date {
  return new Date(now.getTime() + INVITATION_TTL_SECONDS * 1000);
}

/**
 * Builds the link an invitee opens.
 *
 * The token goes in the fragment, which a browser never sends to a server. It
 * therefore stays out of access logs and proxies, and out of the `Referer` header of
 * anything the page loads; the page reads it with {@link invitationTokenFromFragment}
 * and presents it in a request body.
 *
 * @param issuer - The endpoint's issuer identifier.
 * @param token - The opaque invitation token.
 * @returns The invitation page's URL, carrying the token.
 * @example
 * invitationUrl("https://signet.example.org/t/demo/e/main", "abc");
 * // => "https://signet.example.org/t/demo/e/main/invitation#abc"
 */
export function invitationUrl(issuer: string, token: string): string {
  return `${issuer}/invitation#${token}`;
}

/** The alphabet `generateOpaqueToken` writes in: unpadded base64url. */
const TOKEN_PATTERN = /^[A-Za-z0-9_-]+$/;

/**
 * Reads the token back out of an invitation link's fragment.
 *
 * @param fragment - `location.hash`, with or without its leading `#`.
 * @returns The token, or undefined when the fragment holds nothing that
 *   {@link invitationUrl} could have written.
 */
export function invitationTokenFromFragment(
  fragment: string,
): string | undefined {
  const token = fragment.startsWith("#") ? fragment.slice(1) : fragment;
  return TOKEN_PATTERN.test(token) ? token : undefined;
}
