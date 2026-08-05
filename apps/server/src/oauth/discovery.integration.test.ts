/**
 * Discovery, JWKS and issuer resolution against a real database.
 *
 * The most valuable assertion here is the one about Pathling: pointing one
 * environment variable at the issuer is the whole integration, and it works only
 * because `openid-configuration` carries the fields Pathling merges into its own
 * SMART configuration. A missing `jwks_uri` or a mistyped `issuer` would break that
 * with no other symptom.
 *
 * Author: John Grimes
 */

import { afterAll, beforeAll, describe, expect, it } from "bun:test";

import { issuerPath } from "../test/flows.js";
import { createTestStack, testDatabaseUrl } from "../test/harness.js";

import type { TestStack } from "../test/harness.js";

const describeWithDatabase =
  testDatabaseUrl === undefined ? describe.skip : describe;

describeWithDatabase("discovery documents", () => {
  let stack: TestStack;

  beforeAll(async () => {
    stack = await createTestStack();
  });

  afterAll(async () => {
    await stack.close();
  });

  it("advertises the issuer the routes are mounted under", async () => {
    const response = await stack.app.request(
      `${issuerPath(stack)}/.well-known/smart-configuration`,
    );
    expect(response.status).toBe(200);

    const document = (await response.json()) as Record<string, string>;
    expect(document["issuer"]).toBe(stack.issuer);
    expect(document["token_endpoint"]).toBe(`${stack.issuer}/token`);
    expect(document["authorization_endpoint"]).toBe(
      `${stack.issuer}/authorize`,
    );
    expect(document["jwks_uri"]).toBe(`${stack.issuer}/jwks`);
  });

  it("derives capabilities from the endpoint's own configuration", async () => {
    const response = await stack.app.request(
      `${issuerPath(stack)}/.well-known/smart-configuration`,
    );
    const document = (await response.json()) as { capabilities: string[] };

    expect(document.capabilities).toContain("launch-ehr");
    expect(document.capabilities).toContain("launch-standalone");
    expect(document.capabilities).toContain("client-public");
    expect(document.capabilities).toContain("permission-v2");
    // The harness turns this one on, and a capability array that did not follow the
    // column would be exactly the lie the conformance suite exists to catch.
    expect(document.capabilities).toContain("authorize-post");
  });

  it("serves the OpenID Connect document Pathling merges from", async () => {
    const response = await stack.app.request(
      `${issuerPath(stack)}/.well-known/openid-configuration`,
    );
    expect(response.status).toBe(200);

    const document = (await response.json()) as Record<string, unknown>;
    // Exactly the fields a resource server needs to verify a Signet token.
    expect(document["issuer"]).toBe(stack.issuer);
    expect(document["jwks_uri"]).toBe(`${stack.issuer}/jwks`);
    // The endpoint's own key, not a fixed list: a verifier configured from this
    // document has to accept exactly what the endpoint signs with, and the
    // fixture endpoint signs with one ES384 key.
    expect(document["id_token_signing_alg_values_supported"]).toEqual([
      "ES384",
    ]);
    expect(document["code_challenge_methods_supported"]).toEqual(["S256"]);
  });

  it("publishes the active signing key and nothing private", async () => {
    const response = await stack.app.request(`${issuerPath(stack)}/jwks`);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("jwk-set+json");

    const document = (await response.json()) as {
      keys: Record<string, unknown>[];
    };
    expect(document.keys).toHaveLength(1);
    const key = document.keys[0];
    expect(key).toMatchObject({ alg: "ES384", use: "sig" });
    expect(key).toHaveProperty("kid");
    expect(key).not.toHaveProperty("d");
  });

  it("answers cross-origin requests, which a browser app needs", async () => {
    const response = await stack.app.request(`${issuerPath(stack)}/jwks`, {
      headers: { origin: "https://app.test" },
    });
    expect(response.headers.get("access-control-allow-origin")).toBe("*");
    // Credentials are deliberately never allowed; see `http/cors.ts`.
    expect(response.headers.get("access-control-allow-credentials")).toBeNull();
  });

  it("answers a preflight for the token endpoint", async () => {
    const response = await stack.app.request(`${issuerPath(stack)}/token`, {
      method: "OPTIONS",
      headers: { origin: "https://app.test" },
    });
    expect(response.status).toBe(204);
    expect(response.headers.get("access-control-allow-methods")).toContain(
      "POST",
    );
  });

  it("does not advertise CORS on the authorization endpoint", async () => {
    const response = await stack.app.request(
      `${issuerPath(stack)}/authorize?client_id=nope`,
    );
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("answers 404 for an unknown endpoint on a known tenant", async () => {
    const response = await stack.app.request(
      `/t/${stack.tenant.slug}/e/nope/.well-known/smart-configuration`,
    );
    expect(response.status).toBe(404);
  });

  it("answers 404 for an unknown tenant, revealing nothing about it", async () => {
    const unknownTenant = await stack.app.request(
      `/t/no-such-tenant/e/fhir/.well-known/smart-configuration`,
    );
    const unknownEndpoint = await stack.app.request(
      `/t/${stack.tenant.slug}/e/nope/.well-known/smart-configuration`,
    );
    expect(unknownTenant.status).toBe(404);
    // The same body either way: distinguishing them would let a caller enumerate
    // which tenants exist on a shared deployment.
    await expect(unknownTenant.json()).resolves.toEqual(
      await unknownEndpoint.json(),
    );
  });
});

describeWithDatabase("an endpoint with capabilities turned off", () => {
  let stack: TestStack;

  beforeAll(async () => {
    stack = await createTestStack({
      endpoint: {
        slug: "fhir",
        name: "Restricted",
        fhirBaseUrl: "https://fhir.test/R4",
        supportsOpenIdConnect: false,
        supportsStandaloneLaunch: false,
        allowsPublicClients: false,
        supportsBackendServices: false,
        supportsV1Scopes: false,
      },
    });
  });

  afterAll(async () => {
    await stack.close();
  });

  it("withdraws the capabilities it does not have", async () => {
    const response = await stack.app.request(
      `${issuerPath(stack)}/.well-known/smart-configuration`,
    );
    const document = (await response.json()) as {
      capabilities: string[];
      grant_types_supported: string[];
      issuer?: string;
    };

    expect(document.capabilities).not.toContain("sso-openid-connect");
    expect(document.capabilities).not.toContain("launch-standalone");
    expect(document.capabilities).not.toContain("client-public");
    expect(document.capabilities).not.toContain("permission-v1");
    expect(document.grant_types_supported).not.toContain("client_credentials");
    // `issuer` is required only for `sso-openid-connect`; an endpoint that issues no
    // ID tokens must not read as an OIDC provider.
    expect(document.issuer).toBeUndefined();
  });
});
