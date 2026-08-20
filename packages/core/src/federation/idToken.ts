/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Validation of an upstream ID token's claims.
 *
 * Pure, and deliberately separate from signature verification, for the same
 * reason `clientAssertion.ts` is: a token with a good signature and the wrong
 * `aud` is a token minted for somebody else. The signature says the provider
 * wrote it; these claims say the provider wrote it *for this deployment, for this
 * sign-in, and recently*.
 *
 * The checks are OpenID Connect Core §3.1.3.7, minus the parts that only apply to
 * a flow Signet does not use. What matters here:
 *
 * `iss` must be the issuer the discovery document was validated against, so a
 * token from one provider cannot be presented as a token from another.
 *
 * `aud` must contain this deployment's client id, and when the token names more
 * than one audience it must also carry an `azp` naming us. A token issued to
 * another relying party of the same provider is otherwise redeemable here, which
 * would let any client of that provider impersonate any of its users.
 *
 * `nonce` must equal the one minted when the browser was sent upstream. This is
 * the check that makes the ID token specific to *this* sign-in: without it, an ID
 * token captured from an earlier session can be injected into a later one.
 *
 * `exp` and `iat` bound it in time. Both get a small skew allowance, because a
 * provider whose clock is a few seconds off is a configuration nuisance rather
 * than an attack, and a generous allowance would widen every replay window.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
 *
 * Author: John Grimes
 */

/**
 * Clock skew tolerated on `exp` and `iat`, in seconds.
 *
 * Sixty seconds. Larger than the thirty allowed on a client assertion, because
 * the clock in question belongs to somebody else's identity provider rather than
 * to a client we have a registration relationship with, and a sign-in that fails
 * for a person standing at a login page is a worse failure mode than a token
 * request that fails for a machine.
 */
export const UPSTREAM_ID_TOKEN_CLOCK_SKEW_SECONDS = 60;

/**
 * The longest age accepted on `iat`, in seconds.
 *
 * Ten minutes. An ID token arrives moments after it is minted, at the end of a
 * redirect the browser made immediately; one that is older than this either sat
 * somewhere it should not have or is being replayed.
 */
export const MAX_UPSTREAM_ID_TOKEN_AGE_SECONDS = 600;

/** The ID token claims Signet reads. Everything else is passed over. */
export interface UpstreamIdTokenClaims {
  readonly iss?: unknown;
  readonly sub?: unknown;
  readonly aud?: unknown;
  readonly azp?: unknown;
  readonly exp?: unknown;
  readonly iat?: unknown;
  readonly nonce?: unknown;
}

/** Why an ID token was refused. */
export type UpstreamIdTokenRefusalCode =
  | "missing-issuer"
  | "issuer-mismatch"
  | "missing-subject"
  | "missing-audience"
  | "audience-mismatch"
  | "missing-azp"
  | "azp-mismatch"
  | "missing-expiry"
  | "expired"
  | "missing-issued-at"
  | "issued-in-the-future"
  | "too-old"
  | "missing-nonce"
  | "nonce-mismatch";

/** An ID token that passed every claim check. */
export interface ValidatedUpstreamIdToken {
  /** The provider's stable identifier for the person, from `sub`. */
  readonly subject: string;
  readonly issuer: string;
}

/** The outcome of validating an ID token's claims. */
export type UpstreamIdTokenValidation =
  | { readonly ok: true; readonly token: ValidatedUpstreamIdToken }
  | {
      readonly ok: false;
      readonly code: UpstreamIdTokenRefusalCode;
      readonly description: string;
    };

/** Everything the validation reads. */
export interface UpstreamIdTokenInput {
  readonly claims: UpstreamIdTokenClaims;
  /** The issuer from the validated discovery document. */
  readonly expectedIssuer: string;
  /** The client id Signet is registered with upstream. */
  readonly clientId: string;
  /** The nonce minted when the browser was sent upstream. */
  readonly expectedNonce: string;
  readonly nowSeconds: number;
}

/** A refusal, built where the reason is known. */
function refuse(
  code: UpstreamIdTokenRefusalCode,
  description: string,
): UpstreamIdTokenValidation {
  return { ok: false, code, description };
}

/** Reads a numeric claim, rejecting the non-finite and the non-numeric. */
function numericClaim(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value)
    ? value
    : undefined;
}

/** Normalises `aud`, which the spec permits to be a string or an array. */
function audiences(value: unknown): readonly string[] {
  if (typeof value === "string") {
    return [value];
  }
  if (Array.isArray(value)) {
    return value.filter((entry): entry is string => typeof entry === "string");
  }
  return [];
}

/**
 * Validates an ID token's claims, given a signature already known good.
 *
 * @param input - The claims and everything they are checked against.
 * @returns The subject to federate, or why the token was refused.
 */
export function validateUpstreamIdToken(
  input: UpstreamIdTokenInput,
): UpstreamIdTokenValidation {
  const { claims } = input;

  if (typeof claims.iss !== "string" || claims.iss.length === 0) {
    return refuse("missing-issuer", "The ID token has no iss");
  }
  if (claims.iss !== input.expectedIssuer) {
    return refuse(
      "issuer-mismatch",
      `The ID token was issued by ${claims.iss}, not ${input.expectedIssuer}`,
    );
  }

  if (typeof claims.sub !== "string" || claims.sub.length === 0) {
    return refuse("missing-subject", "The ID token has no sub");
  }

  const aud = audiences(claims.aud);
  if (aud.length === 0) {
    return refuse("missing-audience", "The ID token has no aud");
  }
  if (!aud.includes(input.clientId)) {
    return refuse(
      "audience-mismatch",
      "The ID token is addressed to another client of this provider",
    );
  }
  // Multiple audiences mean the token was minted for more than one party, and
  // only `azp` says which of them is meant to redeem it. Core §3.1.3.7 requires
  // the check; skipping it is what lets a co-tenant of the provider replay a
  // token here.
  if (aud.length > 1) {
    if (typeof claims.azp !== "string" || claims.azp.length === 0) {
      return refuse(
        "missing-azp",
        "The ID token names several audiences but no azp",
      );
    }
    if (claims.azp !== input.clientId) {
      return refuse(
        "azp-mismatch",
        "The ID token's azp names another client of this provider",
      );
    }
  }

  const exp = numericClaim(claims.exp);
  if (exp === undefined) {
    return refuse("missing-expiry", "The ID token has no exp");
  }
  if (exp + UPSTREAM_ID_TOKEN_CLOCK_SKEW_SECONDS < input.nowSeconds) {
    return refuse("expired", "The ID token has expired");
  }

  const iat = numericClaim(claims.iat);
  if (iat === undefined) {
    return refuse("missing-issued-at", "The ID token has no iat");
  }
  if (iat - UPSTREAM_ID_TOKEN_CLOCK_SKEW_SECONDS > input.nowSeconds) {
    return refuse(
      "issued-in-the-future",
      "The ID token claims to have been issued in the future",
    );
  }
  if (
    iat +
      MAX_UPSTREAM_ID_TOKEN_AGE_SECONDS +
      UPSTREAM_ID_TOKEN_CLOCK_SKEW_SECONDS <
    input.nowSeconds
  ) {
    return refuse(
      "too-old",
      "The ID token is too old to have come from this sign-in",
    );
  }

  if (typeof claims.nonce !== "string" || claims.nonce.length === 0) {
    return refuse("missing-nonce", "The ID token has no nonce");
  }
  if (claims.nonce !== input.expectedNonce) {
    return refuse(
      "nonce-mismatch",
      "The ID token's nonce does not match this sign-in",
    );
  }

  return { ok: true, token: { subject: claims.sub, issuer: claims.iss } };
}
