import { describe, expect, it } from "vitest";

import {
  MAX_UPSTREAM_ID_TOKEN_AGE_SECONDS,
  UPSTREAM_ID_TOKEN_CLOCK_SKEW_SECONDS,
  validateUpstreamIdToken,
} from "./idToken.js";

import type { UpstreamIdTokenClaims } from "./idToken.js";

const ISSUER = "https://idp.example.org";
const CLIENT_ID = "signet";
const NONCE = "nonce-abc";
const NOW = 1_700_000_000;

/** A token that passes every check, before any override. */
function claims(overrides: UpstreamIdTokenClaims = {}): UpstreamIdTokenClaims {
  return {
    iss: ISSUER,
    sub: "user-1",
    aud: CLIENT_ID,
    exp: NOW + 300,
    iat: NOW - 5,
    nonce: NONCE,
    ...overrides,
  };
}

/** Validates a token against the standard expectations. */
function validate(
  overrides: UpstreamIdTokenClaims = {},
  nowSeconds = NOW,
): ReturnType<typeof validateUpstreamIdToken> {
  return validateUpstreamIdToken({
    claims: claims(overrides),
    expectedIssuer: ISSUER,
    clientId: CLIENT_ID,
    expectedNonce: NONCE,
    nowSeconds,
  });
}

/** The refusal code, or undefined when the token was accepted. */
function refusal(
  result: ReturnType<typeof validateUpstreamIdToken>,
): string | undefined {
  return result.ok ? undefined : result.code;
}

describe("validateUpstreamIdToken", () => {
  it("accepts a well-formed token and returns its subject", () => {
    expect(validate()).toEqual({
      ok: true,
      token: { subject: "user-1", issuer: ISSUER },
    });
  });

  it.each([
    [{ iss: undefined }, "missing-issuer"],
    [{ iss: "" }, "missing-issuer"],
    [{ iss: "https://other.example.org" }, "issuer-mismatch"],
    [{ sub: undefined }, "missing-subject"],
    [{ sub: "" }, "missing-subject"],
    [{ aud: undefined }, "missing-audience"],
    [{ aud: [] }, "missing-audience"],
    [{ aud: "someone-else" }, "audience-mismatch"],
    [{ exp: undefined }, "missing-expiry"],
    [{ exp: "soon" }, "missing-expiry"],
    [{ iat: undefined }, "missing-issued-at"],
    [{ nonce: undefined }, "missing-nonce"],
    [{ nonce: "a-different-nonce" }, "nonce-mismatch"],
  ] as const)("refuses %j with %s", (overrides, code) => {
    expect(refusal(validate(overrides))).toBe(code);
  });

  it("refuses a token addressed to several parties with no azp", () => {
    expect(refusal(validate({ aud: [CLIENT_ID, "another-app"] }))).toBe(
      "missing-azp",
    );
  });

  it("refuses a token whose azp names another party", () => {
    expect(
      refusal(
        validate({ aud: [CLIENT_ID, "another-app"], azp: "another-app" }),
      ),
    ).toBe("azp-mismatch");
  });

  it("accepts several audiences when azp names this deployment", () => {
    expect(
      validate({ aud: [CLIENT_ID, "another-app"], azp: CLIENT_ID }).ok,
    ).toBe(true);
  });

  it("accepts a single audience given as a one-element array", () => {
    expect(validate({ aud: [CLIENT_ID] }).ok).toBe(true);
  });

  it("refuses an expired token, allowing for skew", () => {
    const expiry = NOW - 10;
    // Inside the skew allowance: a provider running a few seconds slow.
    expect(validate({ exp: expiry }, NOW).ok).toBe(true);
    expect(
      refusal(
        validate(
          { exp: expiry },
          NOW + UPSTREAM_ID_TOKEN_CLOCK_SKEW_SECONDS + 1,
        ),
      ),
    ).toBe("expired");
  });

  it("refuses a token issued in the future beyond the skew allowance", () => {
    expect(
      refusal(
        validate({ iat: NOW + UPSTREAM_ID_TOKEN_CLOCK_SKEW_SECONDS + 30 }),
      ),
    ).toBe("issued-in-the-future");
  });

  it("refuses a token far older than one redirect", () => {
    const iat = NOW - MAX_UPSTREAM_ID_TOKEN_AGE_SECONDS - 120;
    // Still unexpired - so age is a check the expiry does not subsume, which is
    // the point: a long-lived ID token replayed into a later sign-in.
    expect(refusal(validate({ iat, exp: NOW + 3600 }))).toBe("too-old");
  });
});
