/**
 * What a permission ticket is allowed to be, decided without touching anything.
 *
 * A ticket is a third party's assertion that some patient has permitted some
 * access, and an endpoint that accepts one is trusting an issuer it named in a
 * rule. Three judgements follow from that, and none of them needs a database, a
 * socket or a key: whether the issuer is the one the rule names, whether the
 * ticket is one this endpoint's rule accepts, and what the ticket actually
 * permits. Each is here, as a function over data the grant has already fetched,
 * so that the console's policy simulator and the token endpoint cannot disagree
 * about what a ticket means.
 *
 * The envelope - issuer, identifier, validity - is read by `../trust/claims.ts`,
 * which a software statement is read by too. What is specific to a ticket is what
 * follows it:
 *
 * **The type is checked against the endpoint's list, not against a constant.**
 * The programme exercises one type, and a rule that names none accepts none. That
 * is the refusing default: reading an empty list as "every type" would make a
 * half-configured endpoint honour ticket types nobody chose.
 *
 * **The subject is an identifier, both halves of it.** Resolution is a search for
 * `{system}|{value}`, and half of that pair is not a narrower search - it is a
 * different one, against whatever else on the FHIR server happens to carry the
 * same digits.
 *
 * **A ticket with no scopes is refused.** The ticket is one of the three ceilings
 * on the exchanged token. A ticket that names no scope has no ceiling to
 * contribute, and reading its silence as "everything" is the mistake this whole
 * grant exists to avoid.
 *
 * Author: John Grimes
 */

import { parseScopes } from "../scopes/parse.js";
import {
  isJsonObject,
  PERMITTED_TRUST_ALGORITHMS,
  readTrustedTokenEnvelope,
  textClaim,
} from "../trust/claims.js";

/**
 * How far a ticket's `iat` may run ahead of Signet's clock, in seconds.
 *
 * The same tolerance every token a trusted issuer signs is judged by.
 */
export { TRUST_CLOCK_TOLERANCE_SECONDS as TICKET_CLOCK_TOLERANCE_SECONDS } from "../trust/claims.js";

import type { Scope } from "../scopes/types.js";
import type { TrustedTokenRefusal } from "../trust/claims.js";

/**
 * The grant type an exchange is requested under.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8693
 */
export const TOKEN_EXCHANGE_GRANT_TYPE =
  "urn:ietf:params:oauth:grant-type:token-exchange";

/**
 * The only `subject_token_type` this endpoint reads.
 *
 * A permission ticket is a signed JWT. A request naming any other type is
 * refused rather than having the type ignored: RFC 8693 lets a subject token be
 * several things, and treating an access token as though it were a ticket would
 * accept a credential the issuer never minted for this purpose.
 */
export const JWT_SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";

/** What an exchange returns, per RFC 8693 §2.2.1. */
export const ACCESS_TOKEN_TYPE =
  "urn:ietf:params:oauth:token-type:access_token";

/**
 * The signature algorithms a permission ticket may be signed with.
 *
 * The same closed asymmetric list a software statement is held to - see
 * `../trust/claims.ts` for why it is closed.
 */
export const PERMITTED_TICKET_ALGORITHMS: readonly string[] =
  PERMITTED_TRUST_ALGORITHMS;

/** The identifier a ticket names its subject by. */
export interface TicketSubject {
  /** The identifier system, opaque to Signet and passed through exactly. */
  readonly system: string;
  readonly value: string;
}

/** Why a permission ticket was refused. */
export type TicketRefusal =
  /** The verified payload is not a JSON object. */
  | "not-an-object"
  /** `iss` is absent, or is not the issuer the endpoint's rule names. */
  | "issuer-mismatch"
  /** No `jti`, so the audit trail would have nothing to record instead of the ticket. */
  | "missing-ticket-id"
  /** No `iat`. */
  | "missing-issued-at"
  /** No `exp`, which would permit access indefinitely. */
  | "missing-expiry"
  /** `exp` has passed. */
  | "expired"
  /** `iat` is ahead of Signet's clock by more than the tolerance. */
  | "issued-in-the-future"
  /** `ticket_type` is absent, or is not one the endpoint's rule accepts. */
  | "unsupported-ticket-type"
  /** No subject identifier, or only half of one. */
  | "missing-subject"
  /** No `smart_scopes`, which would bound nothing. */
  | "missing-scopes"
  /** A `smart_scopes` entry is not a SMART scope. */
  | "malformed-scope";

/** What a valid ticket permits. */
export interface ValidatedTicket {
  /** The issuer identifier, as the endpoint's rule names it. */
  readonly issuer: string;
  /** The ticket's `jti`, which is what the audit trail records. */
  readonly ticketId: string;
  readonly ticketType: string;
  readonly subject: TicketSubject;
  /** The ticket's ceiling on the exchanged token's scopes. */
  readonly scopes: readonly Scope[];
  readonly issuedAt: Date;
  readonly expiresAt: Date;
}

/** What one ticket validation is about. */
export interface TicketCheck {
  /** The ticket's claims, as decoded from a payload whose signature verified. */
  readonly claims: unknown;
  /** The issuer the endpoint's ticket rule names. */
  readonly issuer: string;
  /** The ticket types the endpoint's rule accepts. Empty accepts none. */
  readonly acceptedTicketTypes: readonly string[];
  /** The instant the temporal claims are judged against. */
  readonly now: Date;
}

/** The outcome of validating a ticket's claims. */
export type TicketValidation =
  | { readonly ok: true; readonly ticket: ValidatedTicket }
  | {
      readonly ok: false;
      readonly code: TicketRefusal;
      readonly description: string;
    };

/** Builds a refusal of the ticket. */
function refuseTicket(
  code: TicketRefusal,
  description: string,
): TicketValidation {
  return { ok: false, code, description };
}

/**
 * How the shared envelope's refusals read as a ticket's refusals.
 *
 * A total record, so an envelope refusal added later cannot be silently dropped.
 * Only the identifier is renamed: a ticket's `jti` is what the audit trail
 * records in place of the ticket itself, which is a different reason for
 * requiring it from a statement's.
 */
const TICKET_REFUSAL_FOR: Readonly<Record<TrustedTokenRefusal, TicketRefusal>> =
  {
    "not-an-object": "not-an-object",
    "issuer-mismatch": "issuer-mismatch",
    "missing-token-id": "missing-ticket-id",
    "missing-issued-at": "missing-issued-at",
    "missing-expiry": "missing-expiry",
    expired: "expired",
    "issued-in-the-future": "issued-in-the-future",
  };

/** Reads the subject identifier, requiring both halves of it. */
function readSubject(value: unknown): TicketSubject | undefined {
  if (!isJsonObject(value)) {
    return undefined;
  }
  const system = textClaim(value["system"]);
  const subjectValue = textClaim(value["value"]);
  return system === undefined || subjectValue === undefined
    ? undefined
    : { system, value: subjectValue };
}

/**
 * Validates a ticket's claims against the endpoint's ticket issuer rule.
 *
 * The signature is not checked here and cannot be: verifying it needs the
 * issuer's published keys, which is a fetch. The grant verifies first and passes
 * the decoded payload, so every refusal this function gives is about what the
 * issuer said rather than about whether the issuer said it.
 *
 * @param check - The claims, the rule's issuer and accepted types, and the
 *   instant to judge against.
 * @returns What the ticket permits, or why it was refused. Each refusal has its
 *   own code, because the endpoint has to be able to tell an app whose ticket
 *   expired apart from one whose ticket names a type this endpoint does not
 *   accept.
 * @example
 * ```ts
 * const validated = validatePermissionTicket({
 *   claims,
 *   issuer: rule.issuer,
 *   acceptedTicketTypes: rule.acceptedTicketTypes,
 *   now: context.clock(),
 * });
 * ```
 */
export function validatePermissionTicket(check: TicketCheck): TicketValidation {
  const read = readTrustedTokenEnvelope({
    claims: check.claims,
    expectedIssuer: check.issuer,
    now: check.now,
    noun: "permission ticket",
  });
  if (!read.ok) {
    return refuseTicket(TICKET_REFUSAL_FOR[read.code], read.description);
  }
  const envelope = read.envelope;
  // Narrowed by the envelope read above, which refuses anything else first.
  const claims = check.claims as Record<string, unknown>;

  const ticketType = textClaim(claims["ticket_type"]);
  if (
    ticketType === undefined ||
    !check.acceptedTicketTypes.includes(ticketType)
  ) {
    return refuseTicket(
      "unsupported-ticket-type",
      `This endpoint accepts no ticket of type ${ticketType ?? "(absent)"}`,
    );
  }

  const subject = readSubject(claims["subject"]);
  if (subject === undefined) {
    return refuseTicket(
      "missing-subject",
      "The permission ticket's subject must carry both an identifier system and a value",
    );
  }

  const raw = claims["smart_scopes"];
  if (!Array.isArray(raw) || raw.length === 0) {
    return refuseTicket(
      "missing-scopes",
      "The permission ticket names no smart_scopes, so it permits nothing",
    );
  }
  if (!raw.every((entry) => typeof entry === "string")) {
    return refuseTicket(
      "malformed-scope",
      "Every smart_scopes entry must be a SMART scope string",
    );
  }

  const parsed = parseScopes((raw as readonly string[]).join(" "));
  const rejected = parsed.rejected[0];
  if (rejected !== undefined) {
    return refuseTicket(
      "malformed-scope",
      `The permission ticket's scope "${rejected.raw}" could not be parsed: ${rejected.message}`,
    );
  }

  return {
    ok: true,
    ticket: {
      issuer: envelope.issuer,
      ticketId: envelope.tokenId,
      ticketType,
      subject,
      scopes: parsed.scopes,
      issuedAt: envelope.issuedAt,
      expiresAt: envelope.expiresAt,
    },
  };
}
