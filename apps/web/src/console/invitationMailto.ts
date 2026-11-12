/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The email an administrator sends an invitee, as a `mailto:` link.
 *
 * Signet sends no mail. The console hands the message to the administrator's own
 * mail client instead, pre-filled, so the invitation arrives from somebody the
 * invitee knows rather than from an address they have never seen.
 *
 * Every part is percent-encoded. The link itself ends in a fragment, and an
 * unencoded `#` would end the `mailto:` URI at that point and drop the token from
 * the body. Line breaks are CRLF, as RFC 6068 asks.
 *
 * Author: John Grimes
 */

import { formatInstantWithZone } from "../formatting/values.js";

/** What the message says. */
export interface InvitationMessage {
  /** The invitee's address, as the administrator typed it. May be empty. */
  readonly to: string;
  readonly endpointName: string;
  readonly username: string;
  /** The invitation link, carrying its token. */
  readonly url: string;
  /** When the link stops working, as an ISO 8601 instant. */
  readonly expiresAt: string;
}

/**
 * Builds the `mailto:` link that opens the invitation in a mail client.
 *
 * @param message - The recipient and what the message must tell them.
 * @returns A `mailto:` URI with the subject and body filled in.
 * @example
 * invitationMailto({
 *   to: "casey@example.org",
 *   endpointName: "Main",
 *   username: "casey",
 *   url: "https://signet.example.org/t/demo/e/main/invitation#abc",
 *   expiresAt: "2026-11-20T03:00:00.000Z",
 * });
 * // => "mailto:casey@example.org?subject=Your%20account%20on%20Main&body=…"
 */
export function invitationMailto(message: InvitationMessage): string {
  const subject = `Your account on ${message.endpointName}`;
  const body = [
    "Hello,",
    "",
    `You have been given an account on ${message.endpointName}. Your username is ${message.username}.`,
    "",
    "Open this link to choose your password:",
    "",
    message.url,
    "",
    `The link works once, and expires on ${formatInstantWithZone(message.expiresAt)}. If it has expired, ask for a new one.`,
  ].join("\r\n");

  // The `@` is left readable: it is legal there, and some mail clients do not
  // decode an address before using it.
  const to = encodeURIComponent(message.to.trim()).replaceAll("%40", "@");
  return `mailto:${to}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}
