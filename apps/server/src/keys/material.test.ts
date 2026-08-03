import { jwtVerify, importJWK } from "jose";
import { describe, expect, it } from "vitest";

import {
  ENDPOINT_KEY_ALGORITHMS,
  isEndpointKeyAlgorithm,
} from "./algorithms.js";
import { generateEndpointKey, importPrivateEndpointKey } from "./material.js";
import { prepareSigningKey, signClaims } from "./signing.js";

import type { EndpointKey } from "@signet/db";

const MASTER_KEY = "0123456789abcdef0123456789abcdef";

/** Builds the `endpoint_keys` row shape from generated material. */
function rowFrom(
  generated: Awaited<ReturnType<typeof generateEndpointKey>>,
): EndpointKey {
  return {
    id: "00000000-0000-0000-0000-000000000001",
    endpointId: "00000000-0000-0000-0000-000000000002",
    kid: generated.kid,
    algorithm: generated.algorithm,
    publicJwk: generated.publicJwk,
    privateJwkEncrypted: generated.privateJwkEncrypted,
    status: "active",
    createdAt: new Date(0),
    activatedAt: new Date(0),
    retiredAt: null,
  };
}

describe("isEndpointKeyAlgorithm", () => {
  it("accepts the permitted algorithms", () => {
    for (const algorithm of ENDPOINT_KEY_ALGORITHMS) {
      expect(isEndpointKeyAlgorithm(algorithm)).toBe(true);
    }
  });

  it("refuses anything else", () => {
    expect(isEndpointKeyAlgorithm("RS256")).toBe(false);
    expect(isEndpointKeyAlgorithm("none")).toBe(false);
  });
});

describe.each(ENDPOINT_KEY_ALGORITHMS)(
  "generateEndpointKey (%s)",
  (algorithm) => {
    it("publishes a self-describing public JWK", async () => {
      const generated = await generateEndpointKey(algorithm, MASTER_KEY);

      expect(generated.publicJwk).toMatchObject({
        kid: generated.kid,
        alg: algorithm,
        use: "sig",
      });
      // The public half must never carry private key material.
      expect(generated.publicJwk).not.toHaveProperty("d");
      expect(generated.publicJwk).not.toHaveProperty("p");
    });

    it("derives the kid from the key, so the same key always has the same id", async () => {
      const generated = await generateEndpointKey(algorithm, MASTER_KEY);
      const publicOnly = { ...generated.publicJwk };
      delete publicOnly["kid"];
      delete publicOnly["alg"];
      delete publicOnly["use"];

      // Regenerating the thumbprint from the published key reproduces the kid.
      const { calculateJwkThumbprint } = await import("jose");
      await expect(calculateJwkThumbprint(publicOnly)).resolves.toBe(
        generated.kid,
      );
    });

    it("generates a distinct key each time", async () => {
      const a = await generateEndpointKey(algorithm, MASTER_KEY);
      const b = await generateEndpointKey(algorithm, MASTER_KEY);
      expect(a.kid).not.toBe(b.kid);
    });

    it("stores the private half as envelope ciphertext, not as a JWK", async () => {
      const generated = await generateEndpointKey(algorithm, MASTER_KEY);
      expect(generated.privateJwkEncrypted.startsWith("v1.")).toBe(true);
      expect(generated.privateJwkEncrypted).not.toContain("kty");
    });

    it("round-trips the private half", async () => {
      const generated = await generateEndpointKey(algorithm, MASTER_KEY);
      await expect(
        importPrivateEndpointKey(
          generated.privateJwkEncrypted,
          algorithm,
          MASTER_KEY,
        ),
      ).resolves.toBeInstanceOf(CryptoKey);
    });

    it("refuses to decrypt under the wrong master key", async () => {
      const generated = await generateEndpointKey(algorithm, MASTER_KEY);
      await expect(
        importPrivateEndpointKey(
          generated.privateJwkEncrypted,
          algorithm,
          "fedcba9876543210fedcba9876543210",
        ),
      ).rejects.toThrow();
    });

    it("signs a token the published JWK verifies", async () => {
      const generated = await generateEndpointKey(algorithm, MASTER_KEY);
      const load = await prepareSigningKey(rowFrom(generated), MASTER_KEY);
      expect(load.ok).toBe(true);
      if (!load.ok) return;

      const token = await signClaims(
        { iss: "https://signet.example.org/t/demo/e/x", sub: "user-1" },
        load.signingKey,
      );

      const publicKey = await importJWK(generated.publicJwk, algorithm);
      const { payload, protectedHeader } = await jwtVerify(token, publicKey, {
        issuer: "https://signet.example.org/t/demo/e/x",
      });

      expect(payload["sub"]).toBe("user-1");
      expect(protectedHeader.alg).toBe(algorithm);
      expect(protectedHeader.kid).toBe(generated.kid);
      expect(protectedHeader.typ).toBe("JWT");
    });

    it("honours an explicit token type", async () => {
      const generated = await generateEndpointKey(algorithm, MASTER_KEY);
      const load = await prepareSigningKey(rowFrom(generated), MASTER_KEY);
      if (!load.ok) throw new Error("expected a usable key");

      const token = await signClaims({ sub: "s" }, load.signingKey, "at+jwt");
      const header = JSON.parse(
        Buffer.from(token.split(".", 1)[0] ?? "", "base64url").toString("utf8"),
      ) as { typ: string };
      expect(header.typ).toBe("at+jwt");
    });
  },
);

describe("prepareSigningKey", () => {
  it("refuses a row with an algorithm Signet does not sign with", async () => {
    const generated = await generateEndpointKey("RS384", MASTER_KEY);
    const row = {
      ...rowFrom(generated),
      algorithm: "RS256",
    } as unknown as EndpointKey;
    await expect(prepareSigningKey(row, MASTER_KEY)).resolves.toEqual({
      ok: false,
      reason: "unsupported-algorithm",
    });
  });
});
