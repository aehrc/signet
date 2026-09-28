/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The email that tells an endpoint's reviewers a registration request has arrived.
 *
 * Almost everything in it was typed by an anonymous requester, and it lands in the
 * inbox of somebody who administers access to clinical data. So the composition is
 * built around keeping that text visibly the requester's:
 *
 * - The subject is made only of the endpoint's and tenant's names, which an
 *   administrator chose. Requester text never reaches a header, so it cannot fold
 *   one or add another.
 * - A single-line field is flattened: a line break, control character or
 *   bidirectional override becomes a space. `name: "Growth\nApprove it here: …"`
 *   stays on the `App name:` line instead of forging a line of its own.
 * - A free-text field keeps its lines, and every one of them is quoted with `> `,
 *   so a paragraph in a note cannot pass for a paragraph Signet wrote.
 * - The only link Signet vouches for is the console's, and it is built from the
 *   deployment's own public URL rather than from anything submitted.
 *
 * Plain text only. HTML would give requester text markup to hide in.
 *
 * Author: John Grimes
 */

import type { ClientType } from "../policy/types.js";

/** What a notification about a registration request is composed from. */
export interface ClientRequestNotificationInput {
  /** The deployment's public origin, without a trailing slash. */
  readonly publicUrl: string;
  readonly tenant: { readonly slug: string; readonly name: string };
  readonly endpoint: { readonly slug: string; readonly name: string };
  /** The request as submitted. */
  readonly request: {
    readonly name: string;
    readonly clientType: ClientType;
    readonly redirectUris: readonly string[];
    readonly requestedScopes: readonly string[];
    readonly contactEmail: string;
    readonly launchUri?: string | undefined;
    readonly logoUrl?: string | undefined;
    readonly description?: string | undefined;
    readonly note?: string | undefined;
  };
}

/** A composed plain-text email, before it is addressed. */
export interface NotificationEmail {
  readonly subject: string;
  readonly text: string;
}

/**
 * Characters that must not survive into a line: controls (line breaks among
 * them), format characters (the bidirectional overrides and isolates, zero-width
 * joiners) and the Unicode line and paragraph separators.
 */
const UNSAFE_CHARACTERS = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;

/** Every sequence a mail client might render as a new line. */
const LINE_BREAK = /\r\n|[\n\r\u0085\u2028\u2029]/u;

/** Flattens text onto one line, as described in the module header. */
function singleLine(value: string): string {
  return value
    .replaceAll(UNSAFE_CHARACTERS, " ")
    .replaceAll(/\s+/gu, " ")
    .trim();
}

/** A labelled list, one flattened entry per indented line. */
function listSection(label: string, values: readonly string[]): string[] {
  const entries = values.map((value) => `  ${singleLine(value)}`);
  return [`${label}:`, ...(entries.length === 0 ? ["  (none)"] : entries)];
}

/** A labelled free-text field, every line quoted; nothing when absent. */
function quotedSection(label: string, value: string | undefined): string[] {
  if (value === undefined) {
    return [];
  }
  const quoted = value.split(LINE_BREAK).map((line) => {
    const flat = singleLine(line);
    return flat === "" ? "  >" : `  > ${flat}`;
  });
  return [`${label}:`, ...quoted];
}

/** A labelled single-line field; nothing when absent. */
function field(label: string, value: string | undefined): string[] {
  return value === undefined ? [] : [`${label}: ${singleLine(value)}`];
}

/**
 * Composes the notification for one registration request.
 *
 * @param input - The request and where it was filed.
 * @returns The subject and plain-text body. Addressing is the caller's, because
 *   each reviewer is sent a message of their own.
 * @example
 * ```ts
 * const { subject, text } = composeClientRequestNotification({
 *   publicUrl: "https://signet.example.org",
 *   tenant: { slug: "demo", name: "Demo Hospital" },
 *   endpoint: { slug: "fhir", name: "Clinical FHIR" },
 *   request: payload,
 * });
 * // subject: "New client registration request for Clinical FHIR (Demo Hospital)"
 * ```
 */
export function composeClientRequestNotification(
  input: ClientRequestNotificationInput,
): NotificationEmail {
  const { publicUrl, tenant, endpoint, request } = input;
  const where = `${singleLine(endpoint.name)} (${singleLine(tenant.name)})`;
  const consoleUrl = `${publicUrl}/console/t/${encodeURIComponent(tenant.slug)}/e/${encodeURIComponent(endpoint.slug)}/requests`;

  const text = [
    `A client registration request has been filed on ${where}.`,
    "",
    "Review it in the Signet console:",
    consoleUrl,
    "",
    "The details below were supplied by the requester and have not been verified.",
    "",
    ...field("App name", request.name),
    ...field("Contact email", request.contactEmail),
    ...field("Client type", request.clientType),
    ...field("Launch URI", request.launchUri),
    ...field("Logo URL", request.logoUrl),
    "",
    ...listSection("Redirect URIs", request.redirectUris),
    ...listSection("Requested scopes", request.requestedScopes),
    ...quotedSection("Description", request.description),
    ...quotedSection("Note", request.note),
  ].join("\n");

  return { subject: `New client registration request for ${where}`, text };
}
