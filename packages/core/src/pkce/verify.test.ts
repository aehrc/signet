/**
 * Author: John Grimes
 */

import { describe, expect, it } from "vitest";

import {
  computeS256Challenge,
  isValidCodeVerifier,
  verifyPkce,
} from "./verify.js";

/** The official RFC 7636 Appendix B verifier. */
const RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/** The challenge RFC 7636 Appendix B says that verifier must produce. */
const RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/** A minimum-length verifier of a single repeated character. */
const SHORTEST_VERIFIER = "a".repeat(43);

/** A maximum-length verifier. */
const LONGEST_VERIFIER = "a".repeat(128);

describe("computeS256Challenge", () => {
  it("reproduces the RFC 7636 Appendix B vector", async () => {
    await expect(computeS256Challenge(RFC_VERIFIER)).resolves.toBe(
      RFC_CHALLENGE,
    );
  });

  it("produces an unpadded base64url string", async () => {
    const challenge = await computeS256Challenge(RFC_VERIFIER);
    expect(challenge).not.toContain("=");
    expect(challenge).not.toContain("+");
    expect(challenge).not.toContain("/");
    expect(challenge).toMatch(/^[A-Za-z0-9\-_]+$/);
  });

  it("always produces 43 characters, being an unpadded 32 byte digest", async () => {
    const challenges = await Promise.all([
      computeS256Challenge(RFC_VERIFIER),
      computeS256Challenge(SHORTEST_VERIFIER),
      computeS256Challenge(LONGEST_VERIFIER),
      computeS256Challenge(""),
    ]);
    for (const challenge of challenges) {
      expect(challenge).toHaveLength(43);
    }
  });

  it("is deterministic", async () => {
    const first = await computeS256Challenge(SHORTEST_VERIFIER);
    const second = await computeS256Challenge(SHORTEST_VERIFIER);
    expect(first).toBe(second);
  });

  it("differs for verifiers differing in a single character", async () => {
    const first = await computeS256Challenge(SHORTEST_VERIFIER);
    const second = await computeS256Challenge(`${"a".repeat(42)}b`);
    expect(first).not.toBe(second);
  });

  it("matches known digests for other inputs", async () => {
    // SHA-256("") and SHA-256("abc"), base64url without padding.
    await expect(computeS256Challenge("")).resolves.toBe(
      "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
    );
    await expect(computeS256Challenge("abc")).resolves.toBe(
      "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0",
    );
  });
});

describe("isValidCodeVerifier", () => {
  it("accepts the RFC vector and both length bounds", () => {
    expect(isValidCodeVerifier(RFC_VERIFIER)).toBe(true);
    expect(isValidCodeVerifier(SHORTEST_VERIFIER)).toBe(true);
    expect(isValidCodeVerifier(LONGEST_VERIFIER)).toBe(true);
  });

  it("accepts every unreserved character", () => {
    const unreserved =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    expect(unreserved.length).toBeGreaterThanOrEqual(43);
    expect(isValidCodeVerifier(unreserved)).toBe(true);
  });

  it("rejects lengths outside 43 to 128", () => {
    expect(isValidCodeVerifier("")).toBe(false);
    expect(isValidCodeVerifier("a".repeat(42))).toBe(false);
    expect(isValidCodeVerifier("a".repeat(129))).toBe(false);
  });

  it("rejects characters outside the unreserved set", () => {
    for (const bad of ["+", "/", "=", " ", "!", "%", "@", "\n", "é", "\0"]) {
      expect(isValidCodeVerifier(`${"a".repeat(42)}${bad}`)).toBe(false);
    }
  });
});

describe("verifyPkce", () => {
  it("accepts the RFC 7636 Appendix B vector", async () => {
    await expect(
      verifyPkce(RFC_VERIFIER, RFC_CHALLENGE, "S256"),
    ).resolves.toEqual({ ok: true });
  });

  it("rejects the plain method even when the values match", async () => {
    // `plain` challenges are the verifier itself, so this would succeed on a
    // server that supported it. SMART forbids that, so it must not.
    const result = await verifyPkce(RFC_VERIFIER, RFC_VERIFIER, "plain");
    expect(result.ok).toBe(false);
    expect(result).toMatchObject({ code: "unsupported-method" });
  });

  it("rejects an unknown or absent method", async () => {
    for (const method of ["", "S512", "none", "SHA256"]) {
      const result = await verifyPkce(RFC_VERIFIER, RFC_CHALLENGE, method);
      expect(result).toMatchObject({ ok: false, code: "unsupported-method" });
    }
  });

  it("treats the method as case sensitive", async () => {
    await expect(
      verifyPkce(RFC_VERIFIER, RFC_CHALLENGE, "s256"),
    ).resolves.toMatchObject({ ok: false, code: "unsupported-method" });
  });

  it("checks the method before the verifier, so plain is never hashed", async () => {
    const result = await verifyPkce("too-short", "too-short", "plain");
    expect(result).toMatchObject({ code: "unsupported-method" });
  });

  it("rejects a verifier shorter than 43 characters", async () => {
    const verifier = "a".repeat(42);
    const challenge = await computeS256Challenge(verifier);
    const result = await verifyPkce(verifier, challenge, "S256");
    expect(result).toMatchObject({ ok: false, code: "invalid-verifier" });
  });

  it("rejects a verifier longer than 128 characters", async () => {
    const verifier = "a".repeat(129);
    const challenge = await computeS256Challenge(verifier);
    const result = await verifyPkce(verifier, challenge, "S256");
    expect(result).toMatchObject({ ok: false, code: "invalid-verifier" });
  });

  it("rejects a verifier containing a disallowed character", async () => {
    const verifier = `${"a".repeat(42)}+`;
    const challenge = await computeS256Challenge(verifier);
    const result = await verifyPkce(verifier, challenge, "S256");
    expect(result).toMatchObject({ ok: false, code: "invalid-verifier" });
  });

  it("rejects an empty verifier", async () => {
    await expect(verifyPkce("", RFC_CHALLENGE, "S256")).resolves.toMatchObject({
      ok: false,
      code: "invalid-verifier",
    });
  });

  it("rejects a verifier that hashes to a different challenge", async () => {
    const result = await verifyPkce(SHORTEST_VERIFIER, RFC_CHALLENGE, "S256");
    expect(result).toMatchObject({ ok: false, code: "mismatch" });
  });

  it("rejects a challenge differing in a single character", async () => {
    const tampered = `${RFC_CHALLENGE.slice(0, 42)}X`;
    expect(tampered).not.toBe(RFC_CHALLENGE);
    await expect(
      verifyPkce(RFC_VERIFIER, tampered, "S256"),
    ).resolves.toMatchObject({ ok: false, code: "mismatch" });
  });

  it("rejects an empty challenge", async () => {
    await expect(verifyPkce(RFC_VERIFIER, "", "S256")).resolves.toMatchObject({
      ok: false,
      code: "mismatch",
    });
  });

  it("rejects a challenge that is a prefix or extension of the correct one", async () => {
    for (const challenge of [RFC_CHALLENGE.slice(0, 42), `${RFC_CHALLENGE}a`]) {
      await expect(
        verifyPkce(RFC_VERIFIER, challenge, "S256"),
      ).resolves.toMatchObject({ ok: false, code: "mismatch" });
    }
  });

  it("rejects the verifier being replayed as the challenge", async () => {
    await expect(
      verifyPkce(RFC_VERIFIER, RFC_VERIFIER, "S256"),
    ).resolves.toMatchObject({ ok: false, code: "mismatch" });
  });

  it("returns a message on every failure and none on success", async () => {
    const failure = await verifyPkce(RFC_VERIFIER, "nope", "S256");
    expect(Object.keys(failure).toSorted()).toEqual(["code", "message", "ok"]);
    expect(failure).toMatchObject({
      ok: false,
      code: "mismatch",
      message: expect.stringContaining("code_verifier"),
    });

    const success = await verifyPkce(RFC_VERIFIER, RFC_CHALLENGE, "S256");
    expect(Object.keys(success)).toEqual(["ok"]);
  });

  it("accepts every verifier at both length bounds against its own challenge", async () => {
    for (const verifier of [SHORTEST_VERIFIER, LONGEST_VERIFIER]) {
      const challenge = await computeS256Challenge(verifier);
      await expect(verifyPkce(verifier, challenge, "S256")).resolves.toEqual({
        ok: true,
      });
    }
  });
});
