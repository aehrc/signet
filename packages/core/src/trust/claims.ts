/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * What Signet reads out of a token somebody else signed.
 *
 * Two of them exist: a trust anchor's software statement, which vouches for a
 * client registration, and a ticket issuer's permission ticket, which vouches for
 * access to one patient's record. They carry different payloads and are used for
 * entirely different things, but the envelope around both is the same question -
 * did the issuer this endpoint names sign this, when, and until when - and the
 * answer has to be the same in both cases. A second implementation of it would
 * eventually accept a ticket that the registration endpoint would have refused,
 * and the difference would be invisible until somebody went looking for it.
 *
 * So the envelope is here, and both callers map its refusals onto their own
 * vocabulary. That mapping is deliberate rather than incidental: an app whose
 * statement has no `jti` and an app whose ticket has no `jti` are told different
 * things, because in one case the identifier is what records the statement as
 * spent and in the other it is what the audit trail records instead of the
 * ticket.
 *
 * **Absence is never permission.** A token with no `exp` is refused rather than
 * treated as valid indefinitely, and one whose `iat` is in the future beyond the
 * clock tolerance is refused rather than accepted early. Both are the kind of
 * default that reads as harmless and turns out to be the whole of the
 * authorisation.
 *
 * Author: John Grimes
 */

/**
 * The signature algorithms a trusted issuer's token may be signed with.
 *
 * Asymmetric only, because the token is verified against a key the issuer
 * publishes - there is no shared secret to verify an `HS*` signature against, and
 * `none` would make the whole exercise decorative. `ES256` leads because it is
 * what the connectathon programme's issuer mints; the rest are here so an issuer
 * with an RSA estate is not forced to re-key.
 *
 * A closed list rather than "whatever the key says", so an issuer cannot
 * downgrade the algorithm by publishing a key that names a weaker one.
 */
export const PERMITTED_TRUST_ALGORITHMS: readonly string[] = [
  "ES256",
  "ES384",
  "RS256",
  "RS384",
];

/**
 * How far a trusted token's `iat` may run ahead of Signet's clock, in seconds.
 *
 * Two correct clocks disagree by seconds. An hour is not disagreement, it is a
 * token minted to become valid later, and accepting one would let an issuer
 * pre-date what it vouched for.
 */
export const TRUST_CLOCK_TOLERANCE_SECONDS = 60;

/** Whether a value is a JSON object rather than an array, null or a scalar. */
export function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * A non-empty string claim, or undefined for anything else.
 *
 * @param value - The claim as decoded.
 * @returns The string, or undefined when it is absent or empty.
 */
export function textClaim(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

/**
 * A finite numeric claim, or undefined for anything else.
 *
 * @param value - The claim as decoded.
 * @returns The number, or undefined when it is absent or not finite.
 */
export function numericClaim(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value)
    ? value
    : undefined;
}

/**
 * Whether a string has the three dot-separated parts of a compact JWS.
 *
 * @param value - The candidate token.
 * @returns Whether it could be a compact JWS. Says nothing about the signature.
 */
export function isCompactJws(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 3 && parts.every((part) => part.length > 0);
}

/** Why the envelope around a trusted issuer's token was refused. */
export type TrustedTokenRefusal =
  /** The verified payload is not a JSON object. */
  | "not-an-object"
  /** `iss` is absent, or is not the issuer the endpoint's rule names. */
  | "issuer-mismatch"
  /** No `jti`, so there is nothing to record the token by. */
  | "missing-token-id"
  /** No `iat`. */
  | "missing-issued-at"
  /** No `exp`, which would make the token valid indefinitely. */
  | "missing-expiry"
  /** `exp` has passed. */
  | "expired"
  /** `iat` is ahead of Signet's clock by more than the tolerance. */
  | "issued-in-the-future";

/** The envelope claims every trusted token carries. */
export interface TrustedTokenEnvelope {
  /** The issuer identifier, as the endpoint's rule names it. */
  readonly issuer: string;
  /** The token's `jti`. */
  readonly tokenId: string;
  readonly issuedAt: Date;
  readonly expiresAt: Date;
}

/** What one envelope reading is about. */
export interface TrustedTokenCheck {
  /** The claims, as decoded from a payload whose signature verified. */
  readonly claims: unknown;
  /** The issuer the endpoint's rule names. */
  readonly expectedIssuer: string;
  /** The instant the temporal claims are judged against. */
  readonly now: Date;
  /** What to call the token in a refusal, e.g. `permission ticket`. */
  readonly noun: string;
}

/** The outcome of reading the envelope. */
export type TrustedTokenResult =
  | { readonly ok: true; readonly envelope: TrustedTokenEnvelope }
  | {
      readonly ok: false;
      readonly code: TrustedTokenRefusal;
      readonly description: string;
    };

/** Builds a refusal. */
function refuse(
  code: TrustedTokenRefusal,
  description: string,
): TrustedTokenResult {
  return { ok: false, code, description };
}

/**
 * Reads the issuer, identifier and validity of a token a trusted issuer signed.
 *
 * The signature is not checked here and cannot be: verifying it needs the
 * issuer's published keys, which is a fetch. The caller verifies first and passes
 * the decoded payload, so every refusal this function gives is about what the
 * issuer said rather than about whether the issuer said it.
 *
 * @param check - The claims, the issuer the rule names, the instant to judge
 *   against, and what to call the token in a refusal.
 * @returns The envelope, or why it was refused. Each refusal has its own code,
 *   because a caller has to be able to tell an expired token apart from one
 *   signed by somebody this endpoint does not trust.
 * @example
 * ```ts
 * const envelope = readTrustedTokenEnvelope({
 *   claims,
 *   expectedIssuer: rule.issuer,
 *   now: context.clock(),
 *   noun: "permission ticket",
 * });
 * ```
 */
export function readTrustedTokenEnvelope(
  check: TrustedTokenCheck,
): TrustedTokenResult {
  const { claims, noun, now } = check;
  if (!isJsonObject(claims)) {
    return refuse(
      "not-an-object",
      `The ${noun}'s payload is not a JSON object`,
    );
  }

  if (textClaim(claims["iss"]) !== check.expectedIssuer) {
    return refuse(
      "issuer-mismatch",
      `This endpoint accepts a ${noun} from ${check.expectedIssuer} only`,
    );
  }

  const tokenId = textClaim(claims["jti"]);
  if (tokenId === undefined) {
    return refuse("missing-token-id", `The ${noun} has no jti`);
  }

  const issuedAt = numericClaim(claims["iat"]);
  if (issuedAt === undefined) {
    return refuse("missing-issued-at", `The ${noun} has no iat`);
  }

  const expiresAt = numericClaim(claims["exp"]);
  if (expiresAt === undefined) {
    return refuse(
      "missing-expiry",
      `The ${noun} has no exp, and validity without an end is not accepted`,
    );
  }

  const nowSeconds = Math.floor(now.getTime() / 1000);
  if (expiresAt <= nowSeconds) {
    return refuse("expired", `The ${noun} has expired`);
  }
  if (issuedAt > nowSeconds + TRUST_CLOCK_TOLERANCE_SECONDS) {
    return refuse("issued-in-the-future", `The ${noun}'s iat is in the future`);
  }

  return {
    ok: true,
    envelope: {
      issuer: check.expectedIssuer,
      tokenId,
      issuedAt: new Date(issuedAt * 1000),
      expiresAt: new Date(expiresAt * 1000),
    },
  };
}
