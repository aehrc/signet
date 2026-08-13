/**
 * The trust anchor rule, as the admin API accepts it.
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
