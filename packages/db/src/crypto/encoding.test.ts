/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  decodeBase32,
  decodeBase64,
  decodeBase64Url,
  encodeBase32,
  encodeBase64,
  encodeBase64Url,
} from "./encoding.js";

/**
 * The bytes of an ASCII string, for the RFC 4648 vectors.
 *
 * Copied into a plain `ArrayBuffer` view, which is what the decoders return.
 * `TextEncoder` promises only `ArrayBufferLike`, and a `Uint8Array` over a
 * `SharedArrayBuffer` is not the same type as one over an `ArrayBuffer`.
 */
function ascii(text: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(new TextEncoder().encode(text));
}

describe("base64url", () => {
  it("encodes without padding", () => {
    expect(encodeBase64Url(ascii("f"))).toBe("Zg");
    expect(encodeBase64Url(ascii("fo"))).toBe("Zm8");
    expect(encodeBase64Url(ascii("foo"))).toBe("Zm9v");
  });

  it("uses the url-safe alphabet", () => {
    // These two bytes cover the code points where the alphabets differ.
    const bytes = new Uint8Array([0b1111_1011, 0b1111_1111]);
    expect(encodeBase64Url(bytes)).toBe("-_8");
  });

  it("round-trips arbitrary bytes", () => {
    for (let length = 0; length <= 40; length += 1) {
      const bytes = crypto.getRandomValues(new Uint8Array(length));
      expect(decodeBase64Url(encodeBase64Url(bytes))).toStrictEqual(bytes);
    }
  });

  it("rejects padded input, so one byte sequence has one spelling", () => {
    expect(decodeBase64Url("Zg==")).toBeUndefined();
  });

  it("rejects the standard alphabet", () => {
    expect(decodeBase64Url("-_8")).toBeDefined();
    expect(decodeBase64Url("+/8")).toBeUndefined();
  });

  it("rejects non-canonical trailing bits", () => {
    // "Zh" decodes to the same byte as "Zg" under a permissive decoder.
    expect(decodeBase64Url("Zg")).toBeDefined();
    expect(decodeBase64Url("Zh")).toBeUndefined();
  });

  it("rejects whitespace and out-of-alphabet characters", () => {
    expect(decodeBase64Url("Zm 9v")).toBeUndefined();
    expect(decodeBase64Url("Zm9v.")).toBeUndefined();
  });

  it("accepts the empty string as the empty byte sequence", () => {
    expect(decodeBase64Url("")).toStrictEqual(new Uint8Array(0));
  });
});

describe("base64", () => {
  it("encodes with the standard alphabet and no padding", () => {
    const bytes = new Uint8Array([0b1111_1011, 0b1111_1111]);
    expect(encodeBase64(bytes)).toBe("+/8");
    expect(encodeBase64(ascii("f"))).toBe("Zg");
  });

  it("round-trips arbitrary bytes", () => {
    for (let length = 0; length <= 40; length += 1) {
      const bytes = crypto.getRandomValues(new Uint8Array(length));
      expect(decodeBase64(encodeBase64(bytes))).toStrictEqual(bytes);
    }
  });

  it("rejects the url-safe alphabet and padding", () => {
    expect(decodeBase64("-_8")).toBeUndefined();
    expect(decodeBase64("Zg==")).toBeUndefined();
  });
});

describe("base32", () => {
  it("matches the RFC 4648 section 10 vectors, without padding", () => {
    expect(encodeBase32(ascii(""))).toBe("");
    expect(encodeBase32(ascii("f"))).toBe("MY");
    expect(encodeBase32(ascii("fo"))).toBe("MZXQ");
    expect(encodeBase32(ascii("foo"))).toBe("MZXW6");
    expect(encodeBase32(ascii("foob"))).toBe("MZXW6YQ");
    expect(encodeBase32(ascii("fooba"))).toBe("MZXW6YTB");
    expect(encodeBase32(ascii("foobar"))).toBe("MZXW6YTBOI");
  });

  it("round-trips arbitrary bytes", () => {
    for (let length = 0; length <= 40; length += 1) {
      const bytes = crypto.getRandomValues(new Uint8Array(length));
      expect(decodeBase32(encodeBase32(bytes))).toStrictEqual(bytes);
    }
  });

  it("tolerates the ways a human reproduces a secret", () => {
    const expected = ascii("foobar");
    expect(decodeBase32("MZXW6YTBOI")).toStrictEqual(expected);
    expect(decodeBase32("mzxw6ytboi")).toStrictEqual(expected);
    expect(decodeBase32("MZXW 6YTB OI")).toStrictEqual(expected);
    expect(decodeBase32("MZXW6YTBOI======")).toStrictEqual(expected);
  });

  it("rejects characters outside the alphabet", () => {
    // 0, 1 and 8 are excluded from base32 precisely because they are confusable.
    expect(decodeBase32("MZXW6YTB01")).toBeUndefined();
    expect(decodeBase32("MZXW6YTB!!")).toBeUndefined();
  });

  it("rejects a value truncated mid-byte", () => {
    // Eleven characters is 55 bits: six whole bytes and seven bits left over,
    // which no encoder can produce.
    expect(decodeBase32("MZXW6YTBOIA")).toBeUndefined();
    // Ten characters is a legal length, but here the padding bits are not zero.
    expect(decodeBase32("MZXW6YTBOB")).toBeUndefined();
  });
});
