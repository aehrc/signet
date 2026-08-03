import { describe, expect, it } from "vitest";

import { decodeBase64Url, encodeBase64Url } from "./encoding.js";
import { decryptSecret, encryptSecret, EnvelopeError } from "./envelope.js";

/** A master key of the minimum accepted length. */
const MASTER_KEY = "0123456789abcdef0123456789abcdef";

/** A realistic payload: the sort of private key this actually protects. */
const PRIVATE_KEY = JSON.stringify({
  kty: "EC",
  crv: "P-384",
  d: "kkS0v1DzS0h7Cq6mE1JfGkS2fN0xR5oPqT3wZ9aB",
  x: "aXK7Lm9QwErTyUiOpAsDfGhJkLzXcVbNm1Q2w3E4",
  y: "R5t6Y7u8I9o0P1a2S3d4F5g6H7j8K9l0Z1x2C3v4",
});

/** Splits a `v1.iv.ciphertext` value into its three parts. */
function parts(value: string): [string, string, string] {
  const split = value.split(".", 3);
  return [split[0] ?? "", split[1] ?? "", split[2] ?? ""];
}

/** Replaces one part of a `v1.iv.ciphertext` value. */
function withPart(
  value: string,
  index: 0 | 1 | 2,
  replacement: string,
): string {
  const replaced = parts(value);
  replaced[index] = replacement;
  return replaced.join(".");
}

/** The bytes of one part of a `v1.iv.ciphertext` value. */
function bytesOf(value: string, index: 0 | 1 | 2): Uint8Array {
  const decoded = decodeBase64Url(parts(value)[index]);
  if (decoded === undefined) {
    throw new Error("test fixture is not base64url");
  }
  return decoded;
}

/** Flips the lowest bit of one byte of a base64url-encoded part. */
function flipBit(part: string, byteIndex: number): string {
  const decoded = decodeBase64Url(part);
  if (decoded === undefined) {
    throw new Error("test fixture is not base64url");
  }
  const flipped = new Uint8Array(decoded);
  flipped[byteIndex] = (flipped[byteIndex] ?? 0) ^ 1;
  return encodeBase64Url(flipped);
}

/**
 * Attempts a decryption and reports the outcome as a comparable string.
 *
 * Reporting a successful decryption as text rather than throwing means the
 * failure mode that matters most — a tampered ciphertext quietly decrypting —
 * shows up as a mismatched assertion naming the recovered plaintext, instead of
 * a test that passes because nothing was checked.
 */
async function outcomeOf(
  value: string,
  masterKey = MASTER_KEY,
): Promise<string> {
  try {
    const plaintext = await decryptSecret(value, masterKey);
    return `decrypted to ${JSON.stringify(plaintext)}`;
  } catch (error) {
    return error instanceof EnvelopeError
      ? error.reason
      : `unexpected error: ${String(error)}`;
  }
}

describe("encryptSecret", () => {
  it("produces a versioned, self-describing value", async () => {
    const sealed = await encryptSecret("shhh", MASTER_KEY);
    expect(sealed).toMatch(/^v1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+$/);
  });

  it("never contains the plaintext", async () => {
    const sealed = await encryptSecret("literal-secret-value", MASTER_KEY);
    expect(sealed).not.toContain("literal-secret-value");
  });

  it("uses a fresh initialisation vector for every call", async () => {
    // GCM's confidentiality and integrity both collapse if an IV is reused under
    // one key, so this is the single most important property of the scheme.
    const sealed = await Promise.all(
      Array.from({ length: 50 }, () => encryptSecret("same", MASTER_KEY)),
    );
    const ivs = new Set(sealed.map((value) => parts(value)[1]));
    expect(ivs.size).toBe(50);
    expect(new Set(sealed).size).toBe(50);
  });

  it("refuses a master key shorter than 32 characters", async () => {
    let caught: unknown;
    try {
      await encryptSecret("shhh", "tooshort");
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(EnvelopeError);
    expect((caught as EnvelopeError).reason).toBe("invalid-master-key");
  });
});

describe("round trip", () => {
  it.each([
    ["a JWK private key", PRIVATE_KEY],
    ["an upstream client secret", "cs_9f8e7d6c5b4a39281706"],
    ["an empty string", ""],
    ["a single character", "x"],
    ["non-ASCII text", "clé privée — ключ 🔑"],
    ["a PEM block", "-----BEGIN PRIVATE KEY-----\nMIGkAg\n-----END-----\n"],
    ["a long value", "k".repeat(10_000)],
  ])("recovers %s exactly", async (_case, plaintext) => {
    const sealed = await encryptSecret(plaintext, MASTER_KEY);
    await expect(decryptSecret(sealed, MASTER_KEY)).resolves.toBe(plaintext);
  });

  it("recovers a value under a long master key", async () => {
    const key = `${MASTER_KEY}-with-a-much-longer-passphrase-appended`;
    const sealed = await encryptSecret(PRIVATE_KEY, key);
    await expect(decryptSecret(sealed, key)).resolves.toBe(PRIVATE_KEY);
  });
});

describe("decryptSecret", () => {
  it("rejects the wrong master key", async () => {
    const sealed = await encryptSecret(PRIVATE_KEY, MASTER_KEY);
    expect(await outcomeOf(sealed, "fedcba9876543210fedcba9876543210")).toBe(
      "authentication-failed",
    );
  });

  it("rejects a master key that differs in one character", async () => {
    const sealed = await encryptSecret(PRIVATE_KEY, MASTER_KEY);
    expect(await outcomeOf(sealed, `${MASTER_KEY.slice(0, -1)}F`)).toBe(
      "authentication-failed",
    );
  });

  it("rejects a tampered byte anywhere in the ciphertext", async () => {
    const sealed = await encryptSecret("secret-material", MASTER_KEY);
    const ciphertext = parts(sealed)[2];
    const byteCount = bytesOf(sealed, 2).length;
    // 15 bytes of plaintext plus the 16-byte tag: enough to prove the loop below
    // covers both the message and the tag.
    expect(byteCount).toBe(31);

    const outcomes = new Set<string>();
    for (let index = 0; index < byteCount; index += 1) {
      outcomes.add(
        await outcomeOf(withPart(sealed, 2, flipBit(ciphertext, index))),
      );
    }
    expect([...outcomes]).toStrictEqual(["authentication-failed"]);
  });

  it("rejects a tampered byte anywhere in the initialisation vector", async () => {
    const sealed = await encryptSecret("secret-material", MASTER_KEY);
    const iv = parts(sealed)[1];

    const outcomes = new Set<string>();
    for (let index = 0; index < 12; index += 1) {
      outcomes.add(await outcomeOf(withPart(sealed, 1, flipBit(iv, index))));
    }
    expect([...outcomes]).toStrictEqual(["authentication-failed"]);
  });

  it("rejects a ciphertext truncated at any length", async () => {
    const sealed = await encryptSecret("secret-material", MASTER_KEY);
    const bytes = bytesOf(sealed, 2);

    const outcomes = new Set<string>();
    for (let length = 0; length < bytes.length; length += 1) {
      outcomes.add(
        await outcomeOf(
          withPart(sealed, 2, encodeBase64Url(bytes.slice(0, length))),
        ),
      );
    }
    // Below the tag length this is caught structurally; above it, by the tag.
    expect([...outcomes].toSorted()).toStrictEqual([
      "authentication-failed",
      "malformed",
    ]);
  });

  it("rejects a ciphertext with bytes appended", async () => {
    const sealed = await encryptSecret("secret-material", MASTER_KEY);
    const bytes = bytesOf(sealed, 2);
    const extended = new Uint8Array(bytes.length + 1);
    extended.set(bytes);
    expect(
      await outcomeOf(withPart(sealed, 2, encodeBase64Url(extended))),
    ).toBe("authentication-failed");
  });

  it("rejects an unrecognised scheme version", async () => {
    const sealed = await encryptSecret("secret-material", MASTER_KEY);
    expect(await outcomeOf(withPart(sealed, 0, "v2"))).toBe(
      "unsupported-version",
    );
    expect(await outcomeOf(withPart(sealed, 0, "V1"))).toBe(
      "unsupported-version",
    );
    expect(await outcomeOf(withPart(sealed, 0, ""))).toBe(
      "unsupported-version",
    );
  });

  it.each([
    ["an empty value", ""],
    ["a bare ciphertext", "AAAAAAAAAAAAAAAA"],
    ["two parts", "v1.AAAAAAAAAAAAAAAA"],
    ["four parts", "v1.AAAAAAAAAAAAAAAA.AAAA.AAAA"],
  ])("rejects %s as malformed", async (_case, value) => {
    expect(await outcomeOf(value)).toBe("malformed");
  });

  it("rejects an initialisation vector of the wrong length", async () => {
    const sealed = await encryptSecret("secret-material", MASTER_KEY);
    const iv = bytesOf(sealed, 1);
    expect(
      await outcomeOf(withPart(sealed, 1, encodeBase64Url(iv.slice(0, 11)))),
    ).toBe("malformed");
    expect(
      await outcomeOf(withPart(sealed, 1, encodeBase64Url(new Uint8Array(16)))),
    ).toBe("malformed");
  });

  it("rejects non-canonical base64url rather than accepting a second spelling", async () => {
    const sealed = await encryptSecret("secret-material", MASTER_KEY);
    const iv = parts(sealed)[1];
    expect(await outcomeOf(withPart(sealed, 1, `${iv}==`))).toBe("malformed");
    expect(await outcomeOf(withPart(sealed, 2, "not base64!"))).toBe(
      "malformed",
    );
  });

  it("checks the master key before doing any work on a short key", async () => {
    const sealed = await encryptSecret("secret-material", MASTER_KEY);
    expect(await outcomeOf(sealed, "short")).toBe("invalid-master-key");
  });
});
