/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Canonical base64 codecs shared by the secret-handling primitives.
 *
 * Every value in this directory that crosses the database boundary - a token
 * hash, an envelope ciphertext, an Argon2id salt - is text, and each of those
 * encodings has to be canonical: exactly one string per byte sequence. Tokens
 * and launch handles are *looked up by hash*, so a second accepted spelling of
 * the same bytes would be a second key for the same row, and the uniqueness
 * constraints in the schema would no longer mean what they appear to mean.
 *
 * Decoding therefore round-trips through the encoder and rejects anything that
 * does not come back byte-identical, which rules out padding variants, the
 * opposite alphabet, and the non-canonical trailing bits that a permissive
 * decoder silently discards.
 *
 * Author: John Grimes
 */

/** Characters permitted in an unpadded base64url string (RFC 4648 section 5). */
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/;

/**
 * Characters permitted in the base64 variant used by PHC strings - the standard
 * alphabet of RFC 4648 section 4, without padding.
 */
const BASE64_PATTERN = /^[A-Za-z0-9+/]*$/;

/**
 * Encodes bytes as unpadded base64url.
 *
 * @param bytes - The bytes to encode.
 * @returns The encoding, using `-` and `_` and carrying no `=` padding.
 */
export function encodeBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/**
 * Decodes an unpadded base64url string.
 *
 * @param text - The candidate encoding.
 * @returns The decoded bytes, or `undefined` when `text` is not the canonical
 *   unpadded base64url encoding of any byte sequence.
 */
export function decodeBase64Url(
  text: string,
): Uint8Array<ArrayBuffer> | undefined {
  if (!BASE64URL_PATTERN.test(text)) {
    return undefined;
  }
  const bytes = new Uint8Array(Buffer.from(text, "base64url"));
  return encodeBase64Url(bytes) === text ? bytes : undefined;
}

/**
 * Encodes bytes as unpadded standard base64, as PHC strings use.
 *
 * @param bytes - The bytes to encode.
 * @returns The encoding, using `+` and `/` and carrying no `=` padding.
 */
export function encodeBase64(bytes: Uint8Array): string {
  // `base64` is padded, and the PHC string format forbids padding.
  return Buffer.from(bytes).toString("base64").replace(/=+$/, "");
}

/**
 * Decodes an unpadded standard base64 string.
 *
 * @param text - The candidate encoding.
 * @returns The decoded bytes, or `undefined` when `text` is not the canonical
 *   unpadded base64 encoding of any byte sequence.
 */
export function decodeBase64(
  text: string,
): Uint8Array<ArrayBuffer> | undefined {
  if (!BASE64_PATTERN.test(text)) {
    return undefined;
  }
  const bytes = new Uint8Array(Buffer.from(text, "base64"));
  return encodeBase64(bytes) === text ? bytes : undefined;
}

/**
 * Encodes bytes as unpadded upper-case base32 (RFC 4648 section 6).
 *
 * TOTP secrets are base32 because that is what authenticator applications and
 * QR codes carry, and because the alphabet survives being read aloud or typed
 * from a screen.
 *
 * @param bytes - The bytes to encode.
 * @returns The encoding, without `=` padding.
 */
export function encodeBase32(bytes: Uint8Array): string {
  let encoded = "";
  let buffer = 0;
  let bitsHeld = 0;

  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bitsHeld += 8;
    while (bitsHeld >= 5) {
      bitsHeld -= 5;
      encoded += BASE32_ALPHABET.charAt((buffer >> bitsHeld) & 0b1_1111);
    }
  }
  if (bitsHeld > 0) {
    // Left-align the remaining bits, as RFC 4648 requires.
    encoded += BASE32_ALPHABET.charAt((buffer << (5 - bitsHeld)) & 0b1_1111);
  }

  return encoded;
}

/** The RFC 4648 section 6 alphabet. */
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/**
 * Decodes base32, tolerating the ways a human reproduces a shared secret.
 *
 * Unlike the base64 codecs above, this one is deliberately lenient: lower case,
 * grouping whitespace and trailing `=` padding are all accepted. A TOTP secret
 * is never a lookup key - it is only ever read back for one account whose row
 * has already been found - so there is no uniqueness property for a second
 * spelling to undermine, and refusing a secret because it was pasted with
 * spaces would be a usability failure with no security benefit.
 *
 * @param text - The candidate encoding.
 * @returns The decoded bytes, or `undefined` when `text` contains a character
 *   outside the alphabet or ends mid-byte.
 */
export function decodeBase32(
  text: string,
): Uint8Array<ArrayBuffer> | undefined {
  const normalised = text.replaceAll(/[\s=]/g, "").toUpperCase();

  // Within a final group, 1, 3 and 6 characters carry 5, 15 and 30 bits - none of
  // which is a whole number of bytes plus zero padding, so such a length can only
  // mean the value was truncated. The remaining lengths are checked bitwise
  // below.
  if ([1, 3, 6].includes(normalised.length % 8)) {
    return undefined;
  }

  const bytes: number[] = [];
  let buffer = 0;
  let bitsHeld = 0;

  for (const character of normalised) {
    const value = BASE32_ALPHABET.indexOf(character);
    if (value === -1) {
      return undefined;
    }
    buffer = (buffer << 5) | value;
    bitsHeld += 5;
    if (bitsHeld >= 8) {
      bitsHeld -= 8;
      bytes.push((buffer >> bitsHeld) & 0b1111_1111);
    }
  }

  // Leftover bits are permitted only as the zero padding of a whole group; a
  // non-zero remainder means the string was truncated mid-byte.
  if ((buffer & ((1 << bitsHeld) - 1)) !== 0) {
    return undefined;
  }

  return new Uint8Array(bytes);
}
