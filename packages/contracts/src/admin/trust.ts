/**
 * The two trust rules, as the admin API accepts them.
 *
 * Three fields and one rule of its own: both addresses must be well-formed
 * absolute URLs, because an unparseable rule has to be refused at configuration
 * time rather than at registration time. An operator who mistypes a JWKS address
 * should be told so while they are looking at the form, not discover it when the
 * first app that tries to register is refused for a reason that reads like the
 * app's fault.
 *
 * There is no schema for reading a rule back, and nothing here holds key material:
 * the anchor's keys are fetched fresh through the outbound guard on every
 * registration that needs them, which is what stops a withdrawn key verifying
 * indefinitely.
 *
 * Author: John Grimes
 */

import { z } from "zod";

/**
 * How long an endpoint will ever let a statement vouch for, in days.
 *
 * A year at the outside. The rule is a ceiling on a registration nobody reviews,
 * so "forever" is not one of the options; a connectathon wants weeks and a
 * production deployment should want less.
 */
const MAX_VOUCHING_DAYS = 365;

/** Configuring the trust anchor whose statements an endpoint accepts. */
export const trustAnchorWriteSchema = z.object({
  /** Matched exactly against a statement's `iss`, so a trailing slash matters. */
  issuer: z.string().url().max(2048),
  /** Fetched through the outbound guard on every registration. */
  jwksUri: z.string().url().max(2048),
  /**
   * The endpoint's ceiling on a statement's validity.
   *
   * Defaulted rather than required, because the useful default is a short one and
   * an operator who does not set it should get that rather than a validation
   * error they have to read the documentation to answer.
   */
  maxVouchingDays: z.number().int().min(1).max(MAX_VOUCHING_DAYS).default(30),
});

export type TrustAnchorWrite = z.infer<typeof trustAnchorWriteSchema>;

/**
 * The longest an exchanged access token may live, in seconds.
 *
 * A day at the outside, and the useful answers are minutes. A permission ticket
 * authorises one piece of work on one patient's record; a token that outlives the
 * afternoon is a standing grant nobody reviewed.
 */
const MAX_EXCHANGED_TOKEN_LIFETIME_SECONDS = 86_400;

/** The most ticket types one endpoint will enumerate. */
const MAX_TICKET_TYPES = 20;

/** Configuring the issuer whose permission tickets an endpoint exchanges. */
export const ticketIssuerWriteSchema = z.object({
  /** Matched exactly against a ticket's `iss`, so a trailing slash matters. */
  issuer: z.string().url().max(2048),
  /** Fetched through the outbound guard on every exchange. */
  jwksUri: z.string().url().max(2048),
  /**
   * The ticket types this endpoint honours, and the list discovery advertises.
   *
   * Defaulted to none rather than to everything, and an empty list is accepted:
   * a rule naming no type is a rule that refuses every ticket, which is the only
   * safe reading. Reading silence as "all types" would make a half-configured
   * endpoint accept types nobody chose.
   */
  acceptedTicketTypes: z
    .array(z.string().min(1).max(128))
    .max(MAX_TICKET_TYPES)
    .default([]),
  /**
   * The endpoint's ceiling on an exchanged token's lifetime.
   *
   * One of three: the token expires at the earliest of the ticket's remaining
   * validity, the endpoint's own access token lifetime, and this.
   */
  maxTokenLifetimeSecs: z
    .number()
    .int()
    .min(30)
    .max(MAX_EXCHANGED_TOKEN_LIFETIME_SECONDS)
    .default(300),
});

export type TicketIssuerWrite = z.infer<typeof ticketIssuerWriteSchema>;
