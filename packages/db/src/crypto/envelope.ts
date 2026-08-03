/**
 * Envelope encryption for the secrets Signet must be able to read back.
 *
 * Most secrets Signet stores are one-way: passwords and opaque tokens are only
 * ever compared, so they are hashed. Two are not. An endpoint's private signing
 * key has to be loaded to sign an access token, and an upstream IdP's client
 * secret has to be sent to that IdP's token endpoint. Those cannot be hashed, so
 * they are encrypted at rest under `SIGNET_MASTER_KEY`, which lives in the
 * process environment (a Kubernetes secret) and never in the database. A
 * disclosure of the database alone therefore yields no usable signing key.
 *
 * AES-256-GCM is used through Web Crypto: authenticated encryption, so a
 * tampered ciphertext fails loudly rather than decrypting to attacker-chosen
 * bytes, and no additional dependency to bundle.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc5869
 * @see https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
 */

import { decodeBase64Url, encodeBase64Url } from "./encoding.js";

/**
 * The scheme identifier carried by every ciphertext this module produces.
 *
 * Stored values outlive the code that wrote them. Tagging the format means a
 * later scheme — a different cipher, a key-encryption-key per tenant, an
 * external KMS — can be introduced by adding a `v2` branch here, while `v1`
 * rows keep decrypting and are rewritten lazily. An untagged blob would leave
 * no way to tell the two apart other than guessing.
 */
const CURRENT_VERSION = "v1";

/**
 * The HKDF `info` string that binds the derived key to this exact use.
 *
 * The master key is a passphrase-shaped string from the environment, not
 * uniformly random 256-bit material, so it is stretched into an AES key with
 * HKDF-SHA256 rather than used raw. Beyond that, the fixed `info` gives domain
 * separation: if a later version of Signet derives a second key from the same
 * master key for a different purpose, it uses a different `info` and the two
 * keys are unrelated. Changing this string invalidates every stored ciphertext,
 * so it is versioned in step with {@link CURRENT_VERSION} and must never be
 * edited in place.
 */
const HKDF_INFO = "signet/envelope/v1/aes-256-gcm";

/**
 * Minimum accepted master key length, matching the server's configuration
 * check. Enforced here as well so a caller that bypasses `loadConfig` — a
 * migration script, a test — cannot quietly encrypt under a weak key.
 */
const MASTER_KEY_MIN_LENGTH = 32;

/** GCM initialisation vector length in bytes; 96 bits, as NIST SP 800-38D recommends. */
const IV_BYTES = 12;

/** GCM authentication tag length in bits, appended to the ciphertext by Web Crypto. */
const TAG_BITS = 128;

/** Why an envelope operation failed. */
export type EnvelopeErrorReason =
  /** The master key was absent or shorter than {@link MASTER_KEY_MIN_LENGTH}. */
  | "invalid-master-key"
  /** The stored value was not three dot-separated parts, or was not decodable. */
  | "malformed"
  /** The stored value named a scheme this build does not implement. */
  | "unsupported-version"
  /**
   * The GCM tag did not verify: a wrong master key, a truncated ciphertext, or a
   * deliberately altered byte. These are indistinguishable by design, and all
   * three mean the same thing operationally — the plaintext is not recoverable.
   */
  | "authentication-failed";

/**
 * Thrown when a secret cannot be encrypted or decrypted.
 *
 * Failure is an exception here, not a `false` return, precisely because there is
 * no safe fallback. Every caller wants the plaintext; a function that returned
 * an empty string on a tampered ciphertext would let a corrupted signing key
 * propagate into a token-signing path as "the empty key".
 */
export class EnvelopeError extends Error {
  /** Machine-readable cause, for audit records and operator messages. */
  public readonly reason: EnvelopeErrorReason;

  /**
   * @param reason - Machine-readable cause.
   * @param message - Human-readable detail. Never includes key or secret
   *   material, since this text reaches logs.
   */
  public constructor(reason: EnvelopeErrorReason, message: string) {
    super(message);
    this.name = "EnvelopeError";
    this.reason = reason;
  }
}

const utf8 = new TextEncoder();
const utf8Decoder = new TextDecoder();

/**
 * Derives the AES-256-GCM key for a given master key.
 *
 * Re-derived on every call rather than cached: HKDF-SHA256 over a 32-byte input
 * is two HMAC invocations, which is immaterial next to the database round trip
 * that produced the ciphertext, and a cache of `CryptoKey`s keyed by the master
 * key string would be a lookup table of live key material held for the lifetime
 * of the process.
 *
 * @param masterKey - The `SIGNET_MASTER_KEY` value.
 * @throws {EnvelopeError} When the master key is too short to be credible.
 */
async function deriveKey(masterKey: string): Promise<CryptoKey> {
  if (masterKey.length < MASTER_KEY_MIN_LENGTH) {
    throw new EnvelopeError(
      "invalid-master-key",
      `SIGNET_MASTER_KEY must be at least ${MASTER_KEY_MIN_LENGTH} characters`,
    );
  }

  const material = await crypto.subtle.importKey(
    "raw",
    utf8.encode(masterKey),
    "HKDF",
    // Non-extractable: the derived key never needs to be exported, and marking
    // it so keeps it out of any accidental serialisation.
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      // RFC 5869 section 3.1 permits an empty salt, and this key must be
      // reproducible from the master key alone — a random salt would have to be
      // stored somewhere, and the only place available is beside the ciphertext
      // it protects, where it adds nothing an attacker does not already have.
      // Domain separation comes from `info` instead.
      salt: new Uint8Array(0),
      info: utf8.encode(HKDF_INFO),
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Encrypts a secret for storage.
 *
 * @param plaintext - The secret: a PEM or JWK private key, or an upstream client
 *   secret. Encoded as UTF-8, so any string round-trips exactly.
 * @param masterKey - The `SIGNET_MASTER_KEY` value.
 * @returns `v1.<iv>.<ciphertext+tag>`, both parts unpadded base64url. Safe to
 *   store in a `text` column and to compare for equality, though never for
 *   ordering — two encryptions of the same plaintext differ, by design.
 * @throws {EnvelopeError} When the master key is too short.
 */
export async function encryptSecret(
  plaintext: string,
  masterKey: string,
): Promise<string> {
  const key = await deriveKey(masterKey);
  // A fresh random IV per encryption. GCM's security collapses entirely if an
  // IV is ever reused under the same key, so this is never derived from the
  // plaintext or from a counter that a restored database snapshot could rewind.
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));

  const sealed = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      tagLength: TAG_BITS,
      // The version prefix is authenticated but not encrypted, so an attacker
      // cannot relabel a `v1` ciphertext as some future `v2` to steer
      // decryption down a different path.
      additionalData: utf8.encode(CURRENT_VERSION),
    },
    key,
    utf8.encode(plaintext),
  );

  return [
    CURRENT_VERSION,
    encodeBase64Url(iv),
    encodeBase64Url(new Uint8Array(sealed)),
  ].join(".");
}

/**
 * Decrypts a secret produced by {@link encryptSecret}.
 *
 * @param ciphertext - The stored value.
 * @param masterKey - The `SIGNET_MASTER_KEY` value.
 * @returns The original plaintext.
 * @throws {EnvelopeError} On a short master key, a value that is not in this
 *   format, an unrecognised scheme version, or any failure of the GCM tag —
 *   which covers a wrong master key, a truncated value and a single altered
 *   byte anywhere in the IV or ciphertext.
 */
export async function decryptSecret(
  ciphertext: string,
  masterKey: string,
): Promise<string> {
  const parts = ciphertext.split(".");
  if (parts.length !== 3) {
    throw new EnvelopeError(
      "malformed",
      "Encrypted secret must have the form <version>.<iv>.<ciphertext>",
    );
  }

  const [version, ivPart, sealedPart] = parts as [string, string, string];
  if (version !== CURRENT_VERSION) {
    throw new EnvelopeError(
      "unsupported-version",
      `Unsupported encrypted secret version "${version}"`,
    );
  }

  const iv = decodeBase64Url(ivPart);
  const sealed = decodeBase64Url(sealedPart);
  if (iv === undefined || sealed === undefined) {
    throw new EnvelopeError(
      "malformed",
      "Encrypted secret is not canonical base64url",
    );
  }
  if (iv.length !== IV_BYTES) {
    throw new EnvelopeError(
      "malformed",
      `Initialisation vector must be ${IV_BYTES} bytes`,
    );
  }
  // Below the tag length there is not even an empty authenticated message, and
  // Web Crypto would reject it with a less specific error.
  if (sealed.length < TAG_BITS / 8) {
    throw new EnvelopeError("malformed", "Encrypted secret is truncated");
  }

  const key = await deriveKey(masterKey);

  let opened: ArrayBuffer;
  try {
    opened = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
        tagLength: TAG_BITS,
        additionalData: utf8.encode(version),
      },
      key,
      sealed,
    );
  } catch {
    // Web Crypto deliberately reports one undifferentiated `OperationError` for
    // every authentication failure, and that is the right granularity to pass
    // on: distinguishing "wrong key" from "tampered" would tell an attacker
    // which of the two they achieved.
    throw new EnvelopeError(
      "authentication-failed",
      "Encrypted secret failed authentication: wrong master key or altered ciphertext",
    );
  }

  return utf8Decoder.decode(opened);
}
