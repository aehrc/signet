import { describe, expect, it } from "vitest";

import { decodeBase32, encodeBase32 } from "./encoding.js";
import { generateTotpSecret, totpUri, verifyTotp } from "./totp.js";

/**
 * The RFC 6238 appendix B seed for HMAC-SHA1: the ASCII string
 * "12345678901234567890", base32-encoded as an authenticator would carry it.
 */
const RFC_SECRET = encodeBase32(
  new TextEncoder().encode("12345678901234567890"),
);

/**
 * The appendix B vectors, reduced to six digits.
 *
 * RFC 6238 publishes eight-digit values; a six-digit code is the same truncated
 * binary value modulo 10^6, which is exactly the last six digits.
 */
const VECTORS: [atSeconds: number, code: string][] = [
  [59, "287082"],
  [1_111_111_109, "081804"],
  [1_111_111_111, "050471"],
  [1_234_567_890, "005924"],
  [2_000_000_000, "279037"],
  // Past 2^32 seconds, which catches an implementation that builds the counter
  // with 32-bit arithmetic.
  [20_000_000_000, "353130"],
];

describe("RFC 6238 test vectors", () => {
  it("encodes the published seed as the well-known base32 string", () => {
    expect(RFC_SECRET).toBe("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
  });

  it.each(VECTORS)("accepts the code for T=%i", (atSeconds, code) => {
    // Window 0: the vector must match the current step exactly, not merely fall
    // inside a tolerated drift window.
    expect(verifyTotp(RFC_SECRET, code, atSeconds, 0)).toBe(true);
  });

  it.each(VECTORS)("rejects a neighbouring code at T=%i", (atSeconds, code) => {
    const wrong = String((Number(code) + 1) % 1_000_000).padStart(6, "0");
    expect(verifyTotp(RFC_SECRET, wrong, atSeconds, 0)).toBe(false);
  });
});

describe("verifyTotp", () => {
  const code = "287082";

  it("accepts the code anywhere inside its own thirty-second step", () => {
    for (const atSeconds of [30, 45, 59]) {
      expect(verifyTotp(RFC_SECRET, code, atSeconds, 0)).toBe(true);
    }
  });

  it("tolerates one step of drift on each side by default", () => {
    // The code belongs to the step covering 30 to 59 seconds. 29 is the step
    // before and 60 the step after; both are accepted by default, so a user who
    // started typing just before a boundary is not rejected.
    expect(verifyTotp(RFC_SECRET, code, 29)).toBe(true);
    expect(verifyTotp(RFC_SECRET, code, 60)).toBe(true);
    // Two steps away is outside the default tolerance.
    expect(verifyTotp(RFC_SECRET, code, 90)).toBe(false);
    expect(verifyTotp(RFC_SECRET, code, 120)).toBe(false);
  });

  it("honours a wider window when one is asked for", () => {
    expect(verifyTotp(RFC_SECRET, code, 90, 1)).toBe(false);
    expect(verifyTotp(RFC_SECRET, code, 90, 2)).toBe(true);
  });

  it("accepts only the current step when the window is zero", () => {
    expect(verifyTotp(RFC_SECRET, code, 29, 0)).toBe(false);
    expect(verifyTotp(RFC_SECRET, code, 60, 0)).toBe(false);
  });

  it("does not read the clock", () => {
    // The same arguments always give the same answer, however long the process
    // has been running — the property that makes this testable at all.
    expect(verifyTotp(RFC_SECRET, code, 59, 0)).toBe(true);
    expect(verifyTotp(RFC_SECRET, code, 59, 0)).toBe(true);
  });

  it("tolerates a secret pasted with spaces or in lower case", () => {
    expect(verifyTotp(RFC_SECRET.toLowerCase(), code, 59, 0)).toBe(true);
    expect(
      verifyTotp(RFC_SECRET.replaceAll(/(.{4})/g, "$1 ").trim(), code, 59, 0),
    ).toBe(true);
  });

  it.each([
    ["too short", "28708"],
    ["too long", "2870820"],
    ["padded with spaces", " 287082"],
    ["grouped", "287 082"],
    ["empty", ""],
    ["non-numeric", "abcdef"],
    ["hexadecimal", "0x1234"],
    ["signed", "-87082"],
    ["non-ASCII digits", "٢٨٧٠٨٢"],
  ])("rejects a code that is %s", (_case, presented) => {
    expect(verifyTotp(RFC_SECRET, presented, 59, 0)).toBe(false);
  });

  it("rejects a secret that is not base32", () => {
    expect(verifyTotp("not-base-32!", "287082", 59)).toBe(false);
    // 0, 1 and 8 are outside the alphabet.
    expect(verifyTotp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJ1", "287082", 59)).toBe(
      false,
    );
  });

  it("rejects a secret with less than 128 bits of material", () => {
    // Fails closed: a short secret means the row was not written by Signet.
    const short = encodeBase32(new Uint8Array(8));
    expect(verifyTotp(short, "000000", 59)).toBe(false);
  });

  it("rejects a nonsensical time or window rather than throwing", () => {
    expect(verifyTotp(RFC_SECRET, "287082", Number.NaN)).toBe(false);
    expect(verifyTotp(RFC_SECRET, "287082", Number.POSITIVE_INFINITY)).toBe(
      false,
    );
    expect(verifyTotp(RFC_SECRET, "287082", -1)).toBe(false);
    expect(verifyTotp(RFC_SECRET, "287082", 59, -1)).toBe(false);
    expect(verifyTotp(RFC_SECRET, "287082", 59, 1.5)).toBe(false);
  });

  it("skips negative counters near the epoch instead of throwing", () => {
    // A window reaching below step zero must simply not consider those steps,
    // and must still find a match inside the part of the window that is valid.
    expect(verifyTotp(RFC_SECRET, "287082", 0, 5)).toBe(true);
    expect(verifyTotp(RFC_SECRET, "999999", 0, 5)).toBe(false);
  });
});

describe("generateTotpSecret", () => {
  it("returns 160 bits as 32 base32 characters", () => {
    expect(generateTotpSecret()).toMatch(/^[A-Z2-7]{32}$/);
  });

  it("does not repeat", () => {
    const secrets = new Set(
      Array.from({ length: 500 }, () => generateTotpSecret()),
    );
    expect(secrets.size).toBe(500);
  });

  it("returns 20 decodable bytes, the HMAC-SHA1 digest length", () => {
    const decoded = decodeBase32(generateTotpSecret());
    expect(decoded).toBeDefined();
    expect(decoded?.length).toBe(20);
  });

  it("produces a secret long enough to pass the verifier's own guard", () => {
    // The 128-bit floor rejects a secret Signet did not write, so a generated
    // secret must clear it — otherwise every enrolment would fail closed.
    const secret = generateTotpSecret();
    const decoded = decodeBase32(secret);
    expect(decoded?.length).toBeGreaterThanOrEqual(16);
  });
});

describe("totpUri", () => {
  it("builds an otpauth URI with every parameter stated explicitly", () => {
    expect(totpUri("GEZDGNBVGY3TQOJQ", "admin@example.org", "Signet")).toBe(
      "otpauth://totp/Signet:admin%40example.org" +
        "?secret=GEZDGNBVGY3TQOJQ&issuer=Signet" +
        "&algorithm=SHA1&digits=6&period=30",
    );
  });

  it("percent-encodes a space rather than using a plus sign", () => {
    const uri = totpUri("GEZDGNBVGY3TQOJQ", "admin@example.org", "Signet Demo");
    expect(uri).toContain("otpauth://totp/Signet%20Demo:admin%40example.org");
    expect(uri).toContain("issuer=Signet%20Demo");
    expect(uri).not.toContain("+");
  });

  it("encodes a colon in either component, so the label stays unambiguous", () => {
    const uri = totpUri("GEZDGNBVGY3TQOJQ", "a:b", "c:d");
    expect(uri.startsWith("otpauth://totp/c%3Ad:a%3Ab?")).toBe(true);
  });

  it("refuses a blank account or issuer", () => {
    expect(() => totpUri("GEZDGNBVGY3TQOJQ", "", "Signet")).toThrow(TypeError);
    expect(() => totpUri("GEZDGNBVGY3TQOJQ", "  ", "Signet")).toThrow(
      TypeError,
    );
    expect(() => totpUri("GEZDGNBVGY3TQOJQ", "admin", " ")).toThrow(TypeError);
  });
});
