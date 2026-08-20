/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Validation of a `private_key_jwt` client assertion's claims.
 *
 * Pure: the signature is verified elsewhere, against a JWKS this module knows
 * nothing about. What is decided here is everything that remains once the
 * signature is known good, and it is not a formality - an assertion with a valid
 * signature and the wrong `aud` is a token minted for another authorization
 * server, replayed against this one.
 *
 * Three claims carry the weight.
 *
 * `aud` must be this endpoint's token URL. RFC 7523 §3 requires the assertion to
 * name its intended recipient, and SMART Backend Services makes that the token
 * endpoint. Accepting any audience would let an assertion the client sent to a
 * different Signet endpoint - or to an entirely different vendor's server - be
 * replayed here.
 *
 * `sub` must equal `iss`, and both must be the client id. That is what makes the
 * assertion a statement about *itself* rather than about a third party.
 *
 * `jti` must be present, and `exp` bounded. Neither is verifiable in isolation:
 * the caller books the `jti` against the client in the replay ledger, using the
 * `exp` returned here as the sweep boundary. This module's job is to guarantee
 * the caller has both values and that `exp` is not so far in the future that the
 * ledger row would live forever.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7523#section-3
 * @see https://hl7.org/fhir/smart-app-launch/backend-services.html#protocol-details
 *
 * Author: John Grimes
 */

/** Signing algorithms SMART permits for a client assertion. */
export const PERMITTED_ASSERTION_ALGORITHMS: readonly string[] = [
  "RS384",
  "ES384",
];

/**
 * The longest assertion lifetime accepted, in seconds.
 *
 * SMART recommends five minutes. Accepting an unbounded `exp` would mean keeping
 * the corresponding replay-ledger row for as long as the client chose, so an
 * assertion valid for a year would pin a row for a year - and a client that
 * issues long-lived assertions has built a bearer token, which is the thing
 * `private_key_jwt` exists to avoid.
 */
export const MAX_ASSERTION_LIFETIME_SECONDS = 300;

/**
 * Clock skew tolerated on `exp`, in seconds.
 *
 * Applied to expiry only, and deliberately small. A client whose clock is minutes
 * fast produces assertions that appear expired; a generous allowance here would
 * instead widen every replay window by the same amount.
 */
export const ASSERTION_CLOCK_SKEW_SECONDS = 30;

/** The assertion claims Signet reads. Everything else is passed over. */
export interface ClientAssertionClaims {
  readonly iss?: unknown;
  readonly sub?: unknown;
  readonly aud?: unknown;
  readonly exp?: unknown;
  readonly nbf?: unknown;
  readonly iat?: unknown;
  readonly jti?: unknown;
}

/** Why an assertion was refused. */
export type AssertionRefusalCode =
  | "missing-issuer"
  | "missing-subject"
  | "issuer-subject-mismatch"
  | "client-id-mismatch"
  | "missing-audience"
  | "audience-mismatch"
  | "missing-jti"
  | "missing-expiry"
  | "expired"
  | "not-yet-valid"
  | "lifetime-too-long"
  | "unsupported-algorithm";

/** An assertion that passed every claim check. */
export interface ValidatedClientAssertion {
  /** The client the assertion authenticates, from `sub`. */
  readonly clientId: string;
  readonly jti: string;
  /** The assertion's own expiry, and the replay ledger's sweep boundary. */
  readonly expiresAt: Date;
}

/** The outcome of validating an assertion's claims. */
export type ClientAssertionValidation =
  | { readonly ok: true; readonly assertion: ValidatedClientAssertion }
  | {
      readonly ok: false;
      readonly code: AssertionRefusalCode;
      readonly description: string;
    };

/** Everything the validation reads. */
export interface ClientAssertionInput {
  readonly claims: ClientAssertionClaims;
  /** The `alg` from the protected header. */
  readonly algorithm: string | undefined;
  /**
   * Audiences this endpoint accepts.
   *
   * The token URL is the correct value. The issuer is also accepted because a
   * number of SMART client libraries send it, and the spec's own examples are
   * inconsistent - but both are exact strings belonging to this endpoint, so
   * neither widens the assertion beyond it.
   */
  readonly acceptedAudiences: readonly string[];
  /** The `client_id` the request also carried, when it carried one. */
  readonly presentedClientId: string | undefined;
  /** Seconds since the epoch, from the caller's clock. */
  readonly nowSeconds: number;
}

/** Builds a failed validation. */
function refuse(
  code: AssertionRefusalCode,
  description: string,
): ClientAssertionValidation {
  return { ok: false, code, description };
}

/** Reads a claim that must be a non-empty string. */
function stringClaim(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

/** Reads a claim that must be a finite number, as JWT numeric dates are. */
function numericClaim(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value)
    ? value
    : undefined;
}

/**
 * Whether the assertion's `aud` names one of the accepted audiences.
 *
 * `aud` may be a string or an array of strings; a single member of the array
 * matching is sufficient, which is what RFC 7519 §4.1.3 requires.
 */
function audienceAccepted(
  aud: unknown,
  accepted: readonly string[],
): boolean | undefined {
  if (typeof aud === "string") {
    return accepted.includes(aud);
  }
  if (Array.isArray(aud)) {
    const values = aud.filter(
      (entry): entry is string => typeof entry === "string",
    );
    return values.length === 0
      ? undefined
      : values.some((entry) => accepted.includes(entry));
  }
  return undefined;
}

/**
 * Validates a decoded client assertion's claims.
 *
 * @param input - The decoded claims, the header algorithm, and the context they
 *   are judged against.
 */
export function validateClientAssertion(
  input: ClientAssertionInput,
): ClientAssertionValidation {
  const { claims, nowSeconds } = input;

  if (
    input.algorithm === undefined ||
    !PERMITTED_ASSERTION_ALGORITHMS.includes(input.algorithm)
  ) {
    return refuse(
      "unsupported-algorithm",
      `Client assertions must be signed with ${PERMITTED_ASSERTION_ALGORITHMS.join(" or ")}`,
    );
  }

  const iss = stringClaim(claims.iss);
  if (iss === undefined) {
    return refuse("missing-issuer", "The client assertion has no iss claim");
  }
  const sub = stringClaim(claims.sub);
  if (sub === undefined) {
    return refuse("missing-subject", "The client assertion has no sub claim");
  }
  if (iss !== sub) {
    return refuse(
      "issuer-subject-mismatch",
      "A client assertion's iss and sub must both be the client_id",
    );
  }
  if (
    input.presentedClientId !== undefined &&
    input.presentedClientId !== sub
  ) {
    return refuse(
      "client-id-mismatch",
      "The client assertion's sub does not match the client_id in the request",
    );
  }

  const audience = audienceAccepted(claims.aud, input.acceptedAudiences);
  if (audience === undefined) {
    return refuse("missing-audience", "The client assertion has no aud claim");
  }
  if (!audience) {
    return refuse(
      "audience-mismatch",
      "The client assertion's aud is not this endpoint's token endpoint",
    );
  }

  const jti = stringClaim(claims.jti);
  if (jti === undefined) {
    return refuse(
      "missing-jti",
      "The client assertion has no jti claim, so replay cannot be prevented",
    );
  }

  const exp = numericClaim(claims.exp);
  if (exp === undefined) {
    return refuse("missing-expiry", "The client assertion has no exp claim");
  }
  if (exp <= nowSeconds - ASSERTION_CLOCK_SKEW_SECONDS) {
    return refuse("expired", "The client assertion has expired");
  }
  if (exp > nowSeconds + MAX_ASSERTION_LIFETIME_SECONDS) {
    return refuse(
      "lifetime-too-long",
      `A client assertion may not be valid for more than ${String(MAX_ASSERTION_LIFETIME_SECONDS)} seconds`,
    );
  }

  const nbf = numericClaim(claims.nbf);
  if (nbf !== undefined && nbf > nowSeconds + ASSERTION_CLOCK_SKEW_SECONDS) {
    return refuse("not-yet-valid", "The client assertion is not yet valid");
  }

  return {
    ok: true,
    assertion: { clientId: sub, jti, expiresAt: new Date(exp * 1000) },
  };
}
