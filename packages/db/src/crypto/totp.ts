/**
 * Time-based one-time passwords (RFC 6238) for console administrator accounts.
 *
 * A console administrator can hold a whole tenant's endpoints, keys and
 * policies, so a stolen password must not be sufficient. TOTP is chosen over
 * anything more modern because it needs no enrolment infrastructure: the
 * operator scans a QR code with an application they already have.
 *
 * The parameters are the interoperable ones - HMAC-SHA1, six digits, a
 * thirty-second step - because those are what every authenticator application
 * actually implements. SHA-1 is not a weakness here: HMAC-SHA1 has no practical
 * break, and the value it protects is a six-digit code that expires in seconds.
 *
 * Time is always an argument. Reading the clock inside these functions would
 * make them impossible to test against the published vectors and impossible to
 * reason about at a step boundary, so the caller passes the seconds and this
 * module stays pure.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6238
 * @see https://datatracker.ietf.org/doc/html/rfc4226
 * @see https://github.com/google/google-authenticator/wiki/Key-Uri-Format
 *
 * Author: John Grimes
 */

import { createHmac } from "node:crypto";

import { decodeBase32, encodeBase32 } from "./encoding.js";
import { timingSafeEqual } from "./tokens.js";

/** Seconds per time step: RFC 6238 section 4 default, and universally assumed. */
const STEP_SECONDS = 30;

/** Digits in a generated code. */
const DIGITS = 6;

/** The modulus applied to the truncated HMAC to produce {@link DIGITS} digits. */
const MODULUS = 10 ** DIGITS;

/**
 * Length of a generated shared secret in bytes.
 *
 * 160 bits, which RFC 4226 section 4 recommends and which equals the HMAC-SHA1
 * block digest size - a longer secret would be hashed down and buy nothing.
 * Base32-encodes to exactly 32 characters with no padding.
 */
const SECRET_BYTES = 20;

/**
 * Shortest secret accepted at verification: 128 bits, the minimum RFC 4226
 * section 4 requires. A shorter secret means the row was seeded by something
 * that is not Signet, and it fails closed rather than being honoured.
 */
const MIN_SECRET_BYTES = 16;

/** Codes are exactly {@link DIGITS} ASCII digits; no spaces, no sign, no unicode digits. */
const CODE_PATTERN = new RegExp(String.raw`^\d{${DIGITS}}$`);

/**
 * Mints a shared secret for a new enrolment.
 *
 * @returns 160 bits of CSPRNG output as unpadded upper-case base32 - the form an
 *   authenticator application expects, whether scanned from a QR code or typed.
 */
export function generateTotpSecret(): string {
  return encodeBase32(crypto.getRandomValues(new Uint8Array(SECRET_BYTES)));
}

/**
 * Computes the HOTP value for one counter (RFC 4226 section 5.3).
 *
 * @param secret - The shared secret bytes.
 * @param counter - The step counter, as a non-negative integer.
 */
function hotp(secret: Uint8Array, counter: number): string {
  // Eight-byte big-endian counter. Written via BigInt because RFC 6238's own
  // vectors include a time past 2^32 seconds, where 32-bit shifting silently
  // wraps.
  const message = new Uint8Array(8);
  let remaining = BigInt(counter);
  for (let index = 7; index >= 0; index -= 1) {
    message[index] = Number(remaining & 0b1111_1111n);
    remaining >>= 8n;
  }

  // `node:crypto` rather than `crypto.subtle`: Web Crypto's HMAC is
  // promise-based, and an asynchronous verifier could not be the pure,
  // synchronous function this module is meant to be. `node:crypto` is a runtime
  // builtin, so it bundles into the single-file server with no dependency.
  const digest = createHmac("sha1", secret).update(message).digest();

  // Dynamic truncation: the low nibble of the last byte selects a four-byte
  // window, whose top bit is masked off so the result is positive on every
  // platform's signed 32-bit interpretation.
  const offset = (digest.at(-1) ?? 0) & 0b1111;
  const binary =
    (((digest[offset] ?? 0) & 0b111_1111) << 24) |
    ((digest[offset + 1] ?? 0) << 16) |
    ((digest[offset + 2] ?? 0) << 8) |
    (digest[offset + 3] ?? 0);

  return String(binary % MODULUS).padStart(DIGITS, "0");
}

/**
 * Verifies a presented code against a shared secret at a given time.
 *
 * @param secret - The base32 shared secret from the database. Lower case and
 *   grouping whitespace are tolerated; anything outside the base32 alphabet
 *   makes this return false.
 * @param code - The code as typed by the user.
 * @param atSeconds - Unix time in seconds, supplied by the caller.
 * @param window - Steps of clock drift tolerated on each side. The default of 1
 *   accepts the previous, current and next code - RFC 6238 section 6's
 *   recommendation, and the smallest window that does not reject a user who
 *   started typing just before a step boundary. Pass 0 to accept only the
 *   current step.
 * @returns True when the code matches. False on a mismatch and on every
 *   malformed input, so a login path never has to catch an exception to reject a
 *   bad code.
 */
export function verifyTotp(
  secret: string,
  code: string,
  atSeconds: number,
  window = 1,
): boolean {
  if (!CODE_PATTERN.test(code)) {
    return false;
  }
  if (!Number.isFinite(atSeconds) || atSeconds < 0) {
    return false;
  }
  if (!Number.isInteger(window) || window < 0) {
    return false;
  }

  const secretBytes = decodeBase32(secret);
  if (secretBytes === undefined || secretBytes.length < MIN_SECRET_BYTES) {
    return false;
  }

  const current = Math.floor(atSeconds / STEP_SECONDS);
  let matched = false;
  for (let offset = -window; offset <= window; offset += 1) {
    const counter = current + offset;
    if (counter < 0) {
      continue;
    }
    // Assigned unconditionally, and the comparison is evaluated first, so the
    // whole window costs the same regardless of which step matched - or whether
    // any did.
    matched = timingSafeEqual(hotp(secretBytes, counter), code) || matched;
  }

  return matched;
}

/**
 * Builds the `otpauth://` URI to render as an enrolment QR code.
 *
 * The algorithm, digit count and period are stated explicitly even though they
 * are the defaults, because some authenticator applications silently assume
 * their own defaults when a parameter is absent, and a mismatch produces codes
 * that are wrong with no explanation.
 *
 * @param secret - The base32 secret from {@link generateTotpSecret}.
 * @param account - Identifies the account, conventionally the email address.
 * @param issuer - The service name shown by the authenticator, e.g. `Signet`.
 * @returns An `otpauth://totp/...` URI. It contains the shared secret in the
 *   clear, so it may be shown once during enrolment and must never be logged,
 *   emailed, or stored.
 * @throws {TypeError} When `account` or `issuer` is blank, which would produce a
 *   URI that authenticators display as an unidentifiable entry.
 */
export function totpUri(
  secret: string,
  account: string,
  issuer: string,
): string {
  if (account.trim().length === 0 || issuer.trim().length === 0) {
    throw new TypeError("A TOTP URI requires a non-empty account and issuer");
  }

  // The label is `issuer:account`, each component percent-encoded so that a
  // colon or space in either cannot change the structure of the path.
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  // Built with `encodeURIComponent` rather than `URLSearchParams`, which encodes
  // a space as `+`. That is correct for form submissions and wrong here: an
  // authenticator that percent-decodes without form semantics would display an
  // issuer with a literal plus sign.
  const query = [
    `secret=${secret}`,
    `issuer=${encodeURIComponent(issuer)}`,
    "algorithm=SHA1",
    `digits=${String(DIGITS)}`,
    `period=${String(STEP_SECONDS)}`,
  ].join("&");

  return `otpauth://totp/${label}?${query}`;
}
