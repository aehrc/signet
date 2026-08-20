/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The trust anchor helper, checked against the properties every suite that uses
 * it will rely on.
 *
 * A test helper that quietly mints an unverifiable statement, or serves a JWKS
 * missing the key it signed with, would make the suites built on it pass for the
 * wrong reason - a refusal asserted as a refusal, produced by a broken fixture
 * rather than by the code under test. So the helper is exercised here against
 * `jose` directly: what it mints verifies against what it publishes, and the
 * failure modes it is asked to produce are the ones it actually produces.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";
import {
  createRemoteJWKSet,
  decodeJwt,
  decodeProtectedHeader,
  jwtVerify,
} from "jose";

import { startTrustAnchor, tamperJws } from "./trustAnchor.js";

/** Reads the anchor's published document, counting as a real relying party would. */
async function fetchJwks(uri: string): Promise<{ readonly keys: unknown[] }> {
  const response = await fetch(uri);
  return (await response.json()) as { readonly keys: unknown[] };
}

describe("startTrustAnchor", () => {
  it("publishes a JWK set on a loopback listener", async () => {
    const anchor = await startTrustAnchor();
    try {
      expect(anchor.jwksUri.startsWith("http://127.0.0.1:")).toBe(true);

      const document = await fetchJwks(anchor.jwksUri);
      expect(document.keys).toHaveLength(1);
      expect(document.keys[0]).toMatchObject({
        kty: "EC",
        crv: "P-256",
        alg: "ES256",
        kid: anchor.keyId,
      });
    } finally {
      await anchor.close();
    }
  });

  it("never publishes a private key", async () => {
    const anchor = await startTrustAnchor();
    try {
      const document = await fetchJwks(anchor.jwksUri);
      // `d` is the private scalar. Publishing it would make every signature the
      // helper produces forgeable by the test it is meant to be evidence for.
      expect(JSON.stringify(document)).not.toContain('"d"');
    } finally {
      await anchor.close();
    }
  });

  it("mints a software statement that verifies against the published keys", async () => {
    const anchor = await startTrustAnchor();
    try {
      const statement = await anchor.mintStatement();
      const verified = await jwtVerify(
        statement,
        createRemoteJWKSet(new URL(anchor.jwksUri)),
      );

      expect(verified.payload.iss).toBe(anchor.issuer);
      expect(typeof verified.payload.jti).toBe("string");
      expect(verified.payload.exp).toBeGreaterThan(
        Math.floor(Date.now() / 1000),
      );
      expect(verified.payload["client_name"]).toBeDefined();
      expect(verified.payload["redirect_uris"]).toBeDefined();
      expect(decodeProtectedHeader(statement).kid).toBe(anchor.keyId);
    } finally {
      await anchor.close();
    }
  });

  it("mints a ticket that verifies against the published keys", async () => {
    const anchor = await startTrustAnchor();
    try {
      const ticket = await anchor.mintTicket();
      const verified = await jwtVerify(
        ticket,
        createRemoteJWKSet(new URL(anchor.jwksUri)),
      );

      expect(verified.payload.iss).toBe(anchor.issuer);
      expect(verified.payload["ticket_type"]).toBe("patient-self-access");
      expect(verified.payload["smart_scopes"]).toBeDefined();
    } finally {
      await anchor.close();
    }
  });

  it("gives every minted token a distinct jti", async () => {
    const anchor = await startTrustAnchor();
    try {
      const first = decodeJwt(await anchor.mintStatement());
      const second = decodeJwt(await anchor.mintStatement());

      // Replay protection is keyed on `jti`, so a helper that reused one would
      // make the second registration in any suite fail as a replay.
      expect(first.jti).not.toBe(second.jti);
    } finally {
      await anchor.close();
    }
  });

  it("overrides claims, so a suite can mint the statement it needs", async () => {
    const anchor = await startTrustAnchor();
    try {
      const statement = await anchor.mintStatement({
        issuer: "https://somebody-else.example.org",
        claims: { client_name: "Renamed", jti: "fixed-jti" },
      });
      const claims = decodeJwt(statement);

      expect(claims.iss).toBe("https://somebody-else.example.org");
      expect(claims.jti).toBe("fixed-jti");
      expect(claims["client_name"]).toBe("Renamed");
    } finally {
      await anchor.close();
    }
  });

  it("mints a statement that has already expired, when asked", async () => {
    const anchor = await startTrustAnchor();
    try {
      const statement = await anchor.mintStatement({ lifetimeSeconds: -60 });
      const claims = decodeJwt(statement);

      expect(claims.exp).toBeLessThan(Math.floor(Date.now() / 1000));
      // The signature is still good: the refusal a suite asserts must come from
      // the expiry check, not from a fixture that also broke the signature.
      await expect(
        jwtVerify(statement, createRemoteJWKSet(new URL(anchor.jwksUri)), {
          clockTolerance: 3600,
        }),
      ).resolves.toBeDefined();
    } finally {
      await anchor.close();
    }
  });

  it("counts the fetches its published keys receive", async () => {
    const anchor = await startTrustAnchor();
    try {
      expect(anchor.jwksFetches()).toBe(0);
      await fetchJwks(anchor.jwksUri);
      await fetchJwks(anchor.jwksUri);

      // What proves a cache under test is caching. A helper that could not count
      // would leave "fetched once" unassertable.
      expect(anchor.jwksFetches()).toBe(2);
    } finally {
      await anchor.close();
    }
  });

  it("rotates to a new published key, leaving the superseded one in the set", async () => {
    const anchor = await startTrustAnchor();
    try {
      const first = anchor.keyId;
      const second = await anchor.addKey();

      expect(second).not.toBe(first);
      expect(anchor.keyId).toBe(second);

      const document = await fetchJwks(anchor.jwksUri);
      expect(
        document.keys.map((key) => (key as { readonly kid: string }).kid),
      ).toEqual([first, second]);

      // Signed by the new key, and verifiable - the ordinary rotation case.
      const statement = await anchor.mintStatement();
      expect(decodeProtectedHeader(statement).kid).toBe(second);
      await expect(
        jwtVerify(statement, createRemoteJWKSet(new URL(anchor.jwksUri))),
      ).resolves.toBeDefined();
    } finally {
      await anchor.close();
    }
  });

  it("withdraws a key, so a statement signed with it stops verifying", async () => {
    const anchor = await startTrustAnchor();
    try {
      const withdrawn = anchor.keyId;
      const statement = await anchor.mintStatement();
      await anchor.addKey();
      anchor.withdrawKey(withdrawn);

      const document = await fetchJwks(anchor.jwksUri);
      expect(
        document.keys.map((key) => (key as { readonly kid: string }).kid),
      ).not.toContain(withdrawn);
      await expect(
        jwtVerify(statement, createRemoteJWKSet(new URL(anchor.jwksUri))),
      ).rejects.toThrow();
    } finally {
      await anchor.close();
    }
  });

  it("signs with a nominated key, so an unknown kid can be produced", async () => {
    const anchor = await startTrustAnchor();
    try {
      const unpublished = await anchor.addKey({ publish: false });
      const statement = await anchor.mintStatement({ kid: unpublished });

      expect(decodeProtectedHeader(statement).kid).toBe(unpublished);
      const document = await fetchJwks(anchor.jwksUri);
      expect(
        document.keys.map((key) => (key as { readonly kid: string }).kid),
      ).not.toContain(unpublished);
    } finally {
      await anchor.close();
    }
  });

  it("answers the JWKS with a failure status, when asked", async () => {
    const anchor = await startTrustAnchor();
    try {
      anchor.failJwksWith(503);
      const response = await fetch(anchor.jwksUri);

      expect(response.status).toBe(503);

      anchor.failJwksWith(undefined);
      expect((await fetch(anchor.jwksUri)).status).toBe(200);
    } finally {
      await anchor.close();
    }
  });

  it("stops listening once closed", async () => {
    const anchor = await startTrustAnchor();
    const uri = anchor.jwksUri;
    await anchor.close();

    // A helper that leaked its socket would leave the test process alive and the
    // next suite fetching a document nobody is serving on purpose.
    await expect(fetch(uri)).rejects.toThrow();
  });
});

describe("tamperJws", () => {
  it("leaves a JWS parseable but unverifiable", async () => {
    const anchor = await startTrustAnchor();
    try {
      const statement = await anchor.mintStatement();
      const tampered = tamperJws(statement);

      expect(tampered).not.toBe(statement);
      expect(tampered.split(".")).toHaveLength(3);
      // The claims still decode, so a suite asserting "the signature did not
      // verify" is asserting exactly that and not "the JWT was malformed".
      expect(decodeJwt(tampered).iss).toBe(anchor.issuer);
      await expect(
        jwtVerify(tampered, createRemoteJWKSet(new URL(anchor.jwksUri))),
      ).rejects.toThrow();
    } finally {
      await anchor.close();
    }
  });
});
