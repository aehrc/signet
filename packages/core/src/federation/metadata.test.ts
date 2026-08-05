/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { supportsPkce, validateUpstreamMetadata } from "./metadata.js";

const ISSUER = "https://idp.example.org";

/** A discovery document with every field Signet needs. */
function document(overrides: Record<string, unknown> = {}): unknown {
  return {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    jwks_uri: `${ISSUER}/jwks`,
    userinfo_endpoint: `${ISSUER}/userinfo`,
    ...overrides,
  };
}

describe("validateUpstreamMetadata", () => {
  it("accepts a complete document and returns the parts Signet uses", () => {
    const result = validateUpstreamMetadata(document(), ISSUER);
    expect(result).toEqual({
      ok: true,
      metadata: {
        issuer: ISSUER,
        authorizationEndpoint: `${ISSUER}/authorize`,
        tokenEndpoint: `${ISSUER}/token`,
        jwksUri: `${ISSUER}/jwks`,
        userinfoEndpoint: `${ISSUER}/userinfo`,
      },
    });
  });

  it("refuses a document issued by somebody else", () => {
    const result = validateUpstreamMetadata(
      document({ issuer: "https://attacker.example.org" }),
      ISSUER,
    );
    expect(result.ok).toBe(false);
    expect(result.ok ? undefined : result.code).toBe("issuer-mismatch");
  });

  it("treats a trailing slash as a different issuer", () => {
    // Not pedantry: the provider will mint `iss` one way or the other, and
    // tolerating the difference here only moves the failure to ID token
    // validation, where it is much harder to diagnose.
    const result = validateUpstreamMetadata(
      document({ issuer: `${ISSUER}/` }),
      ISSUER,
    );
    expect(result.ok).toBe(false);
  });

  it.each([
    ["authorization_endpoint"],
    ["token_endpoint"],
    ["jwks_uri"],
  ] as const)("refuses a document with no %s", (field) => {
    const result = validateUpstreamMetadata(
      document({ [field]: undefined }),
      ISSUER,
    );
    expect(result.ok).toBe(false);
    expect(result.ok ? undefined : result.code).toBe("missing-endpoint");
  });

  it.each([
    ["authorization_endpoint", "http://idp.example.org/authorize"],
    ["token_endpoint", "http://idp.example.org/token"],
    ["jwks_uri", "http://idp.example.org/jwks"],
  ] as const)("refuses a plaintext %s", (field, value) => {
    const result = validateUpstreamMetadata(
      document({ [field]: value }),
      ISSUER,
    );
    expect(result.ok).toBe(false);
    expect(result.ok ? undefined : result.code).toBe("insecure-endpoint");
  });

  it("permits plaintext endpoints only when explicitly allowed", () => {
    const result = validateUpstreamMetadata(
      document({ token_endpoint: "http://idp.example.org/token" }),
      ISSUER,
      { allowInsecureEndpoints: true },
    );
    expect(result.ok).toBe(true);
  });

  it("refuses an endpoint that is not an absolute URL", () => {
    const result = validateUpstreamMetadata(
      document({ token_endpoint: "/token" }),
      ISSUER,
    );
    expect(result.ok ? undefined : result.code).toBe("malformed-endpoint");
  });

  it.each([[null], [undefined], ["a string"], [42]])(
    "refuses %s as a document",
    (value) => {
      const result = validateUpstreamMetadata(value, ISSUER);
      expect(result.ok).toBe(false);
    },
  );

  it("refuses a document with no issuer", () => {
    const result = validateUpstreamMetadata(
      document({ issuer: undefined }),
      ISSUER,
    );
    expect(result.ok ? undefined : result.code).toBe("missing-issuer");
  });

  it("omits the userinfo endpoint when the provider publishes none", () => {
    const result = validateUpstreamMetadata(
      document({ userinfo_endpoint: undefined }),
      ISSUER,
    );
    expect(result.ok && "userinfoEndpoint" in result.metadata).toBe(false);
  });

  it("keeps the advertised algorithm and challenge-method lists", () => {
    const result = validateUpstreamMetadata(
      document({
        code_challenge_methods_supported: ["S256", "plain"],
        id_token_signing_alg_values_supported: ["RS256", "ES256"],
      }),
      ISSUER,
    );
    expect(
      result.ok ? result.metadata.codeChallengeMethods : undefined,
    ).toEqual(["S256", "plain"]);
    expect(
      result.ok ? result.metadata.idTokenSigningAlgorithms : undefined,
    ).toEqual(["RS256", "ES256"]);
  });

  it("drops non-string entries from an advertised list", () => {
    const result = validateUpstreamMetadata(
      document({ code_challenge_methods_supported: ["S256", 7, null] }),
      ISSUER,
    );
    expect(
      result.ok ? result.metadata.codeChallengeMethods : undefined,
    ).toEqual(["S256"]);
  });
});

describe("supportsPkce", () => {
  it("is true when the provider advertises S256", () => {
    const result = validateUpstreamMetadata(
      document({ code_challenge_methods_supported: ["S256"] }),
      ISSUER,
    );
    expect(result.ok && supportsPkce(result.metadata)).toBe(true);
  });

  it("is false when the provider advertises only plain", () => {
    const result = validateUpstreamMetadata(
      document({ code_challenge_methods_supported: ["plain"] }),
      ISSUER,
    );
    expect(result.ok && supportsPkce(result.metadata)).toBe(false);
  });

  it("gives a provider that advertises nothing the benefit of the doubt", () => {
    const result = validateUpstreamMetadata(document(), ISSUER);
    expect(result.ok && supportsPkce(result.metadata)).toBe(true);
  });
});
