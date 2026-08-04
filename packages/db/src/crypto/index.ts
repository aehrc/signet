/**
 * Secret-handling primitives.
 *
 * Everything Signet stores that would be dangerous in an attacker's hands passes
 * through this directory, and nothing here touches the database - these are pure
 * functions over strings, so they are exhaustively unit tested without Postgres.
 *
 * Three treatments, chosen by what the secret is:
 *
 * - Low-entropy and only ever compared - passwords. Argon2id.
 * - High-entropy and only ever compared - authorization codes, refresh tokens,
 *   session cookies, API tokens, launch handles. SHA-256.
 * - Must be recovered in cleartext - endpoint private signing keys, upstream IdP
 *   client secrets. AES-256-GCM under the master key.
 *
 * Plus TOTP, which is not storage at all but belongs with the same review.
 *
 * Author: John Grimes
 */

export { hashPassword, needsRehash, verifyPassword } from "./passwords.js";
export { generateOpaqueToken, hashToken, timingSafeEqual } from "./tokens.js";
export {
  decryptSecret,
  encryptSecret,
  EnvelopeError,
  type EnvelopeErrorReason,
} from "./envelope.js";
export { generateTotpSecret, totpUri, verifyTotp } from "./totp.js";
