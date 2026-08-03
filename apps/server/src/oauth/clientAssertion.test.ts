import { describe, expect, it } from "vitest";

import {
  MAX_ASSERTION_LIFETIME_SECONDS,
  validateClientAssertion,
} from "./clientAssertion.js";

import type {
  ClientAssertionClaims,
  ClientAssertionInput,
} from "./clientAssertion.js";

const TOKEN_URL = "https://signet.example.org/t/demo/e/pathling/token";
const ISSUER = "https://signet.example.org/t/demo/e/pathling";
const NOW = 1_800_000_000;

const claims: ClientAssertionClaims = {
  iss: "backend-app",
  sub: "backend-app",
  aud: TOKEN_URL,
  exp: NOW + 60,
  jti: "assertion-1",
};

function validate(
  overrides: {
    claims?: Partial<ClientAssertionClaims>;
    input?: Partial<Omit<ClientAssertionInput, "claims">>;
  } = {},
) {
  return validateClientAssertion({
    claims: { ...claims, ...overrides.claims },
    algorithm: "RS384",
    acceptedAudiences: [TOKEN_URL, ISSUER],
    presentedClientId: undefined,
    nowSeconds: NOW,
    ...overrides.input,
  });
}

describe("validateClientAssertion", () => {
  it("accepts a well-formed assertion", () => {
    const result = validate();
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.assertion).toEqual({
      clientId: "backend-app",
      jti: "assertion-1",
      expiresAt: new Date((NOW + 60) * 1000),
    });
  });

  it("accepts ES384", () => {
    expect(validate({ input: { algorithm: "ES384" } }).ok).toBe(true);
  });

  it.each(["RS256", "HS256", "none", undefined])(
    "refuses the %s algorithm",
    (algorithm) => {
      const result = validate({ input: { algorithm } });
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.code).toBe("unsupported-algorithm");
    },
  );

  it("refuses a missing iss", () => {
    expect(validate({ claims: { iss: undefined } })).toMatchObject({
      code: "missing-issuer",
    });
  });

  it("refuses a missing sub", () => {
    expect(validate({ claims: { sub: undefined } })).toMatchObject({
      code: "missing-subject",
    });
  });

  it("refuses iss and sub naming different clients", () => {
    expect(validate({ claims: { sub: "other-app" } })).toMatchObject({
      code: "issuer-subject-mismatch",
    });
  });

  it("refuses a sub that contradicts the request's client_id", () => {
    expect(
      validate({ input: { presentedClientId: "other-app" } }),
    ).toMatchObject({ code: "client-id-mismatch" });
  });

  it("accepts a sub that agrees with the request's client_id", () => {
    expect(validate({ input: { presentedClientId: "backend-app" } }).ok).toBe(
      true,
    );
  });

  it("refuses a missing aud", () => {
    expect(validate({ claims: { aud: undefined } })).toMatchObject({
      code: "missing-audience",
    });
  });

  it("refuses another server's aud", () => {
    expect(
      validate({ claims: { aud: "https://other.example/token" } }),
    ).toMatchObject({ code: "audience-mismatch" });
  });

  it("accepts the issuer as an audience", () => {
    expect(validate({ claims: { aud: ISSUER } }).ok).toBe(true);
  });

  it("accepts an aud array containing an accepted value", () => {
    expect(
      validate({ claims: { aud: ["https://other.example/token", TOKEN_URL] } })
        .ok,
    ).toBe(true);
  });

  it("refuses an aud array with no accepted value", () => {
    expect(
      validate({ claims: { aud: ["https://other.example/token"] } }),
    ).toMatchObject({ code: "audience-mismatch" });
  });

  it("treats an empty aud array as absent", () => {
    expect(validate({ claims: { aud: [] } })).toMatchObject({
      code: "missing-audience",
    });
  });

  it("refuses a non-string aud", () => {
    expect(validate({ claims: { aud: 42 } })).toMatchObject({
      code: "missing-audience",
    });
  });

  it("refuses a missing jti, because replay could not be prevented", () => {
    expect(validate({ claims: { jti: undefined } })).toMatchObject({
      code: "missing-jti",
    });
  });

  it("refuses a missing exp", () => {
    expect(validate({ claims: { exp: undefined } })).toMatchObject({
      code: "missing-expiry",
    });
  });

  it("refuses a non-numeric exp", () => {
    expect(validate({ claims: { exp: "soon" } })).toMatchObject({
      code: "missing-expiry",
    });
  });

  it("refuses an expired assertion", () => {
    expect(validate({ claims: { exp: NOW - 120 } })).toMatchObject({
      code: "expired",
    });
  });

  it("tolerates small clock skew on expiry", () => {
    expect(validate({ claims: { exp: NOW - 5 } }).ok).toBe(true);
  });

  it("refuses an assertion valid for longer than the ceiling", () => {
    expect(
      validate({
        claims: { exp: NOW + MAX_ASSERTION_LIFETIME_SECONDS + 60 },
      }),
    ).toMatchObject({ code: "lifetime-too-long" });
  });

  it("accepts an assertion at exactly the ceiling", () => {
    expect(
      validate({ claims: { exp: NOW + MAX_ASSERTION_LIFETIME_SECONDS } }).ok,
    ).toBe(true);
  });

  it("refuses an assertion that is not yet valid", () => {
    expect(validate({ claims: { nbf: NOW + 120 } })).toMatchObject({
      code: "not-yet-valid",
    });
  });

  it("tolerates small clock skew on nbf", () => {
    expect(validate({ claims: { nbf: NOW + 5 } }).ok).toBe(true);
  });

  it("ignores a non-numeric nbf", () => {
    expect(validate({ claims: { nbf: "later" } }).ok).toBe(true);
  });
});
