/**
 * PKCE verification (RFC 7636) for the authorization code grant.
 *
 * SMART App Launch 2.2.0 requires PKCE with `S256` on every authorization code
 * request and forbids servers from supporting `plain`, so only `S256` is
 * implemented here.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7636
 * @see https://hl7.org/fhir/smart-app-launch/app-launch.html
 */

/** The only code challenge method Signet accepts. */
const SUPPORTED_METHOD = "S256";

/** RFC 7636 section 4.1: 43 to 128 characters of unreserved ASCII. */
const VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/;

const BASE64URL_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** Why a PKCE verification failed. */
export type PkceErrorCode =
  /** The challenge method was not `S256`. */
  | "unsupported-method"
  /** The verifier was absent, too short, too long, or badly charactered. */
  | "invalid-verifier"
  /** The verifier did not hash to the stored challenge. */
  | "mismatch";

/**
 * The outcome of verifying a code verifier.
 *
 * Failure is a value rather than an exception: a wrong verifier is an expected
 * authentication outcome, not a programming error, and the caller must be able
 * to map it onto an OAuth error response without a `try`/`catch`.
 */
export type PkceResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly code: PkceErrorCode;
      readonly message: string;
    };

/**
 * Encodes bytes as base64url without padding, per RFC 4648 section 5.
 *
 * Hand-rolled rather than delegated to `btoa` or Node's `Buffer` so the same
 * code runs unchanged in the browser policy simulator and on the server.
 *
 * @param bytes - The bytes to encode.
 */
function base64UrlEncode(bytes: Uint8Array): string {
  let encoded = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index] ?? 0;
    const second = bytes[index + 1];
    const third = bytes[index + 2];

    encoded += BASE64URL_ALPHABET.charAt(first >> 2);
    encoded += BASE64URL_ALPHABET.charAt(
      ((first & 0b11) << 4) | ((second ?? 0) >> 4),
    );
    if (second === undefined) {
      break;
    }
    encoded += BASE64URL_ALPHABET.charAt(
      ((second & 0b1111) << 2) | ((third ?? 0) >> 6),
    );
    if (third === undefined) {
      break;
    }
    encoded += BASE64URL_ALPHABET.charAt(third & 0b11_1111);
  }
  return encoded;
}

/**
 * Compares two strings without leaking where they first differ.
 *
 * A naive comparison short-circuits on the first differing character, which
 * lets an attacker who can time the response recover a challenge byte by byte.
 * The whole of both strings is always walked here.
 *
 * @param left - One string.
 * @param right - The other string.
 */
function constantTimeEquals(left: string, right: string): boolean {
  let difference = left.length ^ right.length;
  const span = Math.max(left.length, right.length);
  for (let index = 0; index < span; index += 1) {
    // Reading past the end gives undefined, folded to 0; a length difference is
    // already in the accumulator above, so that cannot mask one.
    difference |=
      (left.codePointAt(index) ?? 0) ^ (right.codePointAt(index) ?? 0);
  }
  return difference === 0;
}

/**
 * Computes the `S256` code challenge for a code verifier.
 *
 * The verifier is hashed with SHA-256 and the digest base64url-encoded without
 * padding, as required by RFC 7636 section 4.2.
 *
 * @param verifier - The code verifier, as sent by the client.
 * @returns The corresponding code challenge.
 */
export async function computeS256Challenge(verifier: string): Promise<string> {
  const encoded = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  return base64UrlEncode(new Uint8Array(digest));
}

/**
 * True when a string is a syntactically valid RFC 7636 code verifier.
 *
 * @param verifier - The candidate verifier.
 */
export function isValidCodeVerifier(verifier: string): boolean {
  return VERIFIER_PATTERN.test(verifier);
}

/**
 * Verifies a code verifier against the challenge recorded at authorization.
 *
 * @param verifier - The `code_verifier` presented at the token endpoint.
 * @param challenge - The `code_challenge` stored with the authorization code.
 * @param method - The `code_challenge_method` stored with the code. Anything
 *   other than `S256` is refused, including `plain`, which SMART App Launch
 *   forbids servers from supporting.
 * @returns Success, or a typed failure. Never throws for a failed check.
 */
export async function verifyPkce(
  verifier: string,
  challenge: string,
  method: string,
): Promise<PkceResult> {
  if (method !== SUPPORTED_METHOD) {
    return {
      ok: false,
      code: "unsupported-method",
      message: `Unsupported code_challenge_method "${method}"; only S256 is permitted.`,
    };
  }

  if (!isValidCodeVerifier(verifier)) {
    return {
      ok: false,
      code: "invalid-verifier",
      message: "code_verifier must be 43 to 128 characters of [A-Za-z0-9-._~].",
    };
  }

  const computed = await computeS256Challenge(verifier);
  if (!constantTimeEquals(computed, challenge)) {
    return {
      ok: false,
      code: "mismatch",
      message: "code_verifier does not match the recorded code_challenge.",
    };
  }

  return { ok: true };
}
