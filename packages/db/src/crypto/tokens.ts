/**
 * Opaque bearer credentials: generation, storage hashing and comparison.
 *
 * Signet issues opaque random strings for authorization codes, refresh tokens,
 * console session cookies, API tokens and launch handles. All of them are stored
 * as a SHA-256 digest and looked up by that digest, so a disclosure of the
 * database yields nothing replayable.
 *
 * ## Why a fast hash here, and Argon2id for passwords
 *
 * Argon2id exists to make guessing *low-entropy* secrets expensive: a
 * user-chosen password comes from a distribution an attacker can enumerate, so
 * the only defence is to make each attempt cost real time and memory.
 *
 * These tokens are the opposite case. Each is 256 bits straight from the
 * operating system's CSPRNG, so there is no distribution to enumerate — an
 * offline attacker holding the digest has nothing cheaper than 2^255 expected
 * guesses, and no work factor improves on that. A slow hash would buy nothing.
 *
 * It would also cost a great deal. Every token presented at `/token`,
 * `/introspect`, `/revoke` and every console request is looked up by hash, which
 * means one hash per request on the hottest paths in the product. Argon2id at
 * defensible parameters is tens of milliseconds and tens of mebibytes each; an
 * unauthenticated caller could exhaust the process by sending garbage tokens.
 * That is a denial-of-service vulnerability introduced in the name of security.
 *
 * The same reasoning is why the digest is unsalted: a per-token salt could not
 * be looked up by, and a rainbow table over a 256-bit space cannot be built.
 */

import { encodeBase64Url } from "./encoding.js";

/**
 * Bytes of entropy in a generated token.
 *
 * 256 bits, which base64url-encodes to 43 characters. Well beyond the 128 bits
 * that RFC 6749 section 10.10 requires of an authorization code, and chosen to
 * match the SHA-256 digest they are stored as: no part of the chain is the weak
 * link.
 */
const TOKEN_BYTES = 32;

/**
 * Mints a fresh opaque bearer token.
 *
 * The returned value is the *only* copy — the caller stores
 * {@link hashToken}'s output and hands this string to the client, which is why
 * a lost secret can only be replaced, never recovered.
 *
 * @returns 256 bits of CSPRNG output, base64url-encoded without padding.
 */
export function generateOpaqueToken(): string {
  return encodeBase64Url(crypto.getRandomValues(new Uint8Array(TOKEN_BYTES)));
}

/**
 * Computes the stored form of an opaque token.
 *
 * Deterministic and unsalted by design, so a presented token can be turned into
 * a single indexed lookup. See this module's header for why SHA-256 rather than
 * Argon2id is the correct choice for high-entropy values.
 *
 * @param token - The token as presented by the client.
 * @returns The SHA-256 digest, base64url-encoded without padding.
 */
export async function hashToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token),
  );
  return encodeBase64Url(new Uint8Array(digest));
}

/**
 * Compares two strings without revealing where they first differ.
 *
 * A naive `===` short-circuits at the first differing character, so an attacker
 * able to measure response time can recover a secret one character at a time.
 * This walks the whole of both strings and folds every difference, including a
 * difference in length, into one accumulator.
 *
 * Both operands are expected to be the digests or codes this module produces —
 * short, ASCII, and of predictable length. Comparison is per index over code
 * points, which is exact for those and still rejects any pair of differing
 * strings, but it is not a general-purpose byte comparison for arbitrary
 * Unicode.
 *
 * @param a - One string.
 * @param b - The other string.
 * @returns True when the strings are identical.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  let difference = a.length ^ b.length;
  const span = Math.max(a.length, b.length);

  for (let index = 0; index < span; index += 1) {
    // Past the end `codePointAt` gives `undefined`, which the bitwise operators
    // coerce to 0. A length mismatch is already in the accumulator, so that
    // cannot mask one.
    difference |= (a.codePointAt(index) ?? 0) ^ (b.codePointAt(index) ?? 0);
  }

  return difference === 0;
}
