/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * An OAuth / OpenID Connect endpoint, end to end against a real database.
 *
 * The same surfaces a SMART endpoint serves, asked the questions on which the two
 * kinds differ: whose `aud` a token carries and whether a client must say so, what
 * an API scope means, which identity claims sign-in yields, and which SMART-only
 * surfaces refuse. Every refusal here has a SMART counterpart elsewhere in the
 * suite that proves the same surface still answers on the other kind.
 *
 * Author: John Grimes
 */

import {
  OAUTH_BASELINE_PRESET,
  OAUTH_DEFAULT_SCOPES_SUPPORTED,
  TOKEN_EXCHANGE_GRANT_TYPE,
} from "@signet/core";
import { upsertEndpointTicketIssuer, withTenantScope } from "@signet/db";
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { createLocalJWKSet, jwtVerify } from "jose";

import {
  adminJson,
  adminRequest,
  endpointPath,
  tenantPath,
} from "../test/adminApi.js";
import {
  authorize,
  authorizeToCode,
  backendToken,
  basicAuth,
  decodePayload,
  interactionState,
  issuerPath,
  login,
  pkcePair,
  postForm,
  postJson,
  startAuthorization,
} from "../test/flows.js";
import {
  createTestStack,
  TEST_API_AUDIENCE,
  TEST_PASSWORD,
  TEST_USER_EMAIL,
  testDatabaseUrl,
} from "../test/harness.js";

import type { TestStack } from "../test/harness.js";
import type { PolicyDocument } from "@signet/core";

const describeWithDatabase =
  testDatabaseUrl === undefined ? describe.skip : describe;

/** The OAuth baseline, plus one API scope an operator chose to grant. */
const API_POLICY: PolicyDocument = {
  ...OAUTH_BASELINE_PRESET,
  scopeGrants: [
    ...OAUTH_BASELINE_PRESET.scopeGrants,
    {
      id: "grant-orders-read",
      description: "Read your orders.",
      match: "orders:read",
      allow: true,
    },
  ],
};

/** A token response body, as far as these suites read it. */
interface TokenResponseBody {
  readonly access_token: string;
  readonly scope: string;
  readonly id_token?: string;
  readonly refresh_token?: string;
  readonly error?: string;
}

/** The interaction view fields only an OAuth endpoint's pages read. */
interface KindAwareInteraction {
  readonly step: string;
  readonly endpointKind: string;
  readonly scopeDescriptions: Readonly<Record<string, string>>;
}

/** Verifies a token against the endpoint's published JWKS and audience. */
async function verify(
  stack: TestStack,
  token: string,
  audience: string,
): Promise<Record<string, unknown>> {
  const jwks = (await (
    await stack.app.request(`${issuerPath(stack)}/jwks`)
  ).json()) as { keys: Record<string, unknown>[] };
  const { payload } = await jwtVerify(token, createLocalJWKSet(jwks), {
    issuer: stack.issuer,
    audience,
  });
  return payload;
}

/** The error a refused `/authorize` redirect carried back to the app. */
function redirectedError(response: Response): string | null {
  const location = response.headers.get("location") ?? "";
  return new URL(location).searchParams.get("error");
}

/** Files a developer portal request, with any fields overridden. */
async function submitPortalRequest(
  stack: TestStack,
  extra: Record<string, unknown> = {},
): Promise<Response> {
  return await stack.app.request(`${issuerPath(stack)}/apps/requests`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      name: "Portal App",
      contactEmail: "dev@example.org",
      clientType: "public",
      redirectUris: ["https://portal-app.test/cb"],
      requestedScopes: ["openid"],
      ...extra,
    }),
  });
}

/**
 * The discovery URLs the developer portal gives a developer whose request was
 * approved: one from the request's status, one from the app's registration.
 */
async function portalDiscoveryUrls(stack: TestStack): Promise<string[]> {
  const filed = (await (await submitPortalRequest(stack)).json()) as {
    request: { id: string };
    trackingToken: string;
  };
  await adminJson(
    stack,
    "POST",
    endpointPath(stack, `/client-requests/${filed.request.id}/approve`),
    { credential: { cookie: await stack.signIn() }, body: {} },
  );
  const status = (await (
    await stack.app.request(
      `${issuerPath(stack)}/apps/requests/${filed.request.id}`,
      { headers: { authorization: `Bearer ${filed.trackingToken}` } },
    )
  ).json()) as { clientId: string; wellKnown: string };
  const registration = (await (
    await stack.app.request(
      `${issuerPath(stack)}/apps/registration/${status.clientId}`,
    )
  ).json()) as { wellKnown: string };
  return [status.wellKnown, registration.wellKnown];
}

/**
 * Asserts every URL is the named discovery document and that the endpoint serves it.
 */
async function expectServedDiscovery(
  stack: TestStack,
  urls: readonly string[],
  document: "openid-configuration" | "smart-configuration",
): Promise<void> {
  for (const url of urls) {
    expect(url).toBe(`${stack.issuer}/.well-known/${document}`);
    const served = await stack.app.request(new URL(url).pathname);
    expect(served.status).toBe(200);
  }
}

describeWithDatabase("an OAuth / OpenID Connect endpoint", () => {
  let stack: TestStack;

  beforeAll(async () => {
    stack = await createTestStack({
      kind: "oauth",
      policy: API_POLICY,
      endpoint: {
        supportsBackendServices: true,
        supportsDynamicRegistration: true,
      },
    });
  });

  afterAll(async () => {
    await stack.close();
  });

  describe("discovery", () => {
    it("serves openid-configuration with the identity claims it can issue", async () => {
      const response = await stack.app.request(
        `${issuerPath(stack)}/.well-known/openid-configuration`,
      );
      expect(response.status).toBe(200);
      const document = (await response.json()) as {
        issuer: string;
        scopes_supported: string[];
        claims_supported: string[];
      };
      expect(document.issuer).toBe(stack.issuer);
      expect(document.scopes_supported).toContain("email");
      expect(document.claims_supported).toEqual(
        expect.arrayContaining([
          "name",
          "preferred_username",
          "email",
          "email_verified",
        ]),
      );
      expect(document.claims_supported).not.toContain("fhirUser");
    });

    it("answers 404 for smart-configuration", async () => {
      const response = await stack.app.request(
        `${issuerPath(stack)}/.well-known/smart-configuration`,
      );
      expect(response.status).toBe(404);
    });
  });

  describe("/authorize", () => {
    it("accepts a request that names no audience at all", async () => {
      const response = await authorize(stack, {
        clientId: stack.publicClient.clientId,
        scope: "openid profile",
        challenge: (await pkcePair()).challenge,
        aud: null,
      });
      expect(response.status).toBe(302);
      expect(response.headers.get("location")).toContain("/login");
    });

    it("accepts resource and aud values naming the endpoint's audience", async () => {
      const response = await authorize(stack, {
        clientId: stack.publicClient.clientId,
        scope: "openid profile",
        challenge: (await pkcePair()).challenge,
        aud: `${TEST_API_AUDIENCE}/`,
        resources: [TEST_API_AUDIENCE, `${TEST_API_AUDIENCE}/`],
      });
      expect(response.status).toBe(302);
      expect(response.headers.get("location")).toContain("/login");
    });

    it("refuses a resource naming another API with invalid_target", async () => {
      const response = await authorize(stack, {
        clientId: stack.publicClient.clientId,
        scope: "openid profile",
        challenge: (await pkcePair()).challenge,
        aud: null,
        resources: [TEST_API_AUDIENCE, "https://other-api.test/v1"],
      });
      expect(response.status).toBe(302);
      expect(redirectedError(response)).toBe("invalid_target");
    });

    it("refuses an aud naming another API with invalid_target", async () => {
      const response = await authorize(stack, {
        clientId: stack.publicClient.clientId,
        scope: "openid profile",
        challenge: (await pkcePair()).challenge,
        aud: "https://other-api.test/v1",
      });
      expect(redirectedError(response)).toBe("invalid_target");
    });

    it("refuses an EHR launch", async () => {
      const response = await authorize(stack, {
        clientId: stack.publicClient.clientId,
        scope: "openid profile",
        challenge: (await pkcePair()).challenge,
        aud: null,
        launch: "some-handle",
      });
      expect(redirectedError(response)).toBe("invalid_request");
    });

    it("treats a SMART-shaped scope as an opaque string the allowlist does not name", async () => {
      const response = await authorize(stack, {
        clientId: stack.publicClient.clientId,
        scope: "openid patient/Observation.rs",
        challenge: (await pkcePair()).challenge,
        aud: null,
      });
      expect(redirectedError(response)).toBe("invalid_scope");
    });
  });

  describe("the interaction", () => {
    it("never asks for a patient, and describes API scopes by their rule", async () => {
      const session = await startAuthorization(stack, {
        clientId: stack.publicClient.clientId,
        scope: "openid profile orders:read",
        challenge: (await pkcePair()).challenge,
        aud: null,
      });
      const before = (await interactionState(
        stack,
        session,
      )) as unknown as KindAwareInteraction;
      expect(before.endpointKind).toBe("oauth");

      const after = (await (
        await login(stack, session, {
          username: "clinician",
          password: TEST_PASSWORD,
        })
      ).json()) as KindAwareInteraction;
      expect(after.step).toBe("consent");
      expect(after.endpointKind).toBe("oauth");
      expect(after.scopeDescriptions["orders:read"]).toBe("Read your orders.");
    });

    it("refuses a context selection", async () => {
      const session = await startAuthorization(stack, {
        clientId: stack.publicClient.clientId,
        scope: "openid profile",
        challenge: (await pkcePair()).challenge,
        aud: null,
      });
      await login(stack, session, {
        username: "clinician",
        password: TEST_PASSWORD,
      });
      const response = await postJson(
        stack,
        `/interaction/${session}/context`,
        { patient: "pat-1" },
      );
      expect(response.status).toBe(400);
    });
  });

  describe("the authorization_code grant", () => {
    it("issues an access token for the API and an ID token with the identity claims", async () => {
      const { code, verifier } = await authorizeToCode(stack, {
        clientId: stack.publicClient.clientId,
        scope: "openid profile email orders:read orders:write",
        aud: null,
      });
      const response = await postForm(stack, "/token", {
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://app.test/cb",
        code_verifier: verifier,
        client_id: stack.publicClient.clientId,
        resource: TEST_API_AUDIENCE,
      });
      expect(response.status).toBe(200);
      const body = (await response.json()) as TokenResponseBody;

      // Granted because a rule names it; refused because none names it.
      expect(body.scope.split(" ")).toContain("orders:read");
      expect(body.scope.split(" ")).not.toContain("orders:write");

      const access = await verify(stack, body.access_token, TEST_API_AUDIENCE);
      expect(access["aud"]).toBe(TEST_API_AUDIENCE);
      expect(access["fhirUser"]).toBeUndefined();

      const identity = decodePayload(body.id_token ?? "");
      expect(identity["aud"]).toBe(stack.publicClient.clientId);
      expect(identity["name"]).toBe("Test Clinician");
      expect(identity["preferred_username"]).toBe("clinician");
      expect(identity["email"]).toBe(TEST_USER_EMAIL);
      expect(identity["email_verified"]).toBe(true);
      expect(identity["fhirUser"]).toBeUndefined();
      expect(identity["roles"]).toBeUndefined();

      const userinfo = await stack.app.request(
        `${issuerPath(stack)}/userinfo`,
        { headers: { authorization: `Bearer ${body.access_token}` } },
      );
      expect(userinfo.status).toBe(200);
      const claims = (await userinfo.json()) as Record<string, unknown>;
      expect(claims["sub"]).toBe(stack.user.id);
      expect(claims["email"]).toBe(TEST_USER_EMAIL);
      expect(claims["preferred_username"]).toBe("clinician");
    });

    it("refuses a resource naming another API with invalid_target", async () => {
      const { code, verifier } = await authorizeToCode(stack, {
        clientId: stack.publicClient.clientId,
        scope: "openid profile",
        aud: null,
      });
      const response = await postForm(stack, "/token", {
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://app.test/cb",
        code_verifier: verifier,
        client_id: stack.publicClient.clientId,
        resource: "https://other-api.test/v1",
      });
      expect(response.status).toBe(400);
      expect(((await response.json()) as TokenResponseBody).error).toBe(
        "invalid_target",
      );
    });
  });

  describe("the refresh_token grant", () => {
    it("refreshes for the endpoint's audience and refuses another", async () => {
      const { code, verifier } = await authorizeToCode(stack, {
        clientId: stack.symmetricClient.clientId,
        scope: "openid offline_access orders:read",
        aud: null,
      });
      const issued = (await (
        await postForm(
          stack,
          "/token",
          {
            grant_type: "authorization_code",
            code,
            redirect_uri: "https://app.test/cb",
            code_verifier: verifier,
          },
          { authorization: basicAuth(stack.symmetricClient.clientId) },
        )
      ).json()) as TokenResponseBody;
      expect(issued.refresh_token).toBeDefined();

      const refused = await postForm(
        stack,
        "/token",
        {
          grant_type: "refresh_token",
          refresh_token: issued.refresh_token ?? "",
          resource: "https://other-api.test/v1",
        },
        { authorization: basicAuth(stack.symmetricClient.clientId) },
      );
      expect(refused.status).toBe(400);
      expect(((await refused.json()) as TokenResponseBody).error).toBe(
        "invalid_target",
      );

      // The refusal did not spend the token.
      const refreshed = await postForm(
        stack,
        "/token",
        {
          grant_type: "refresh_token",
          refresh_token: issued.refresh_token ?? "",
          resource: TEST_API_AUDIENCE,
        },
        { authorization: basicAuth(stack.symmetricClient.clientId) },
      );
      expect(refreshed.status).toBe(200);
      const body = (await refreshed.json()) as TokenResponseBody;
      const claims = await verify(stack, body.access_token, TEST_API_AUDIENCE);
      expect(claims["scope"]).toContain("orders:read");
    });
  });

  describe("the client_credentials grant", () => {
    it("issues a token for the API's audience", async () => {
      const response = await backendToken(stack, "orders:read");
      expect(response.status).toBe(200);
      const body = (await response.json()) as TokenResponseBody;
      expect(body.scope).toBe("orders:read");
      const claims = await verify(stack, body.access_token, TEST_API_AUDIENCE);
      expect(claims["sub"]).toBe(stack.backendClient.client.clientId);
    });

    it("accepts a resource naming the endpoint's audience", async () => {
      const response = await backendToken(
        stack,
        "orders:read",
        {},
        { resource: TEST_API_AUDIENCE },
      );
      expect(response.status).toBe(200);
    });

    it("refuses a resource naming another API with invalid_target", async () => {
      const response = await backendToken(
        stack,
        "orders:read",
        {},
        { resource: [TEST_API_AUDIENCE, "https://other-api.test/v1"] },
      );
      expect(response.status).toBe(400);
      expect(((await response.json()) as TokenResponseBody).error).toBe(
        "invalid_target",
      );
    });

    it("refuses an API scope no rule names", async () => {
      const response = await backendToken(stack, "orders:write");
      expect(response.status).toBe(400);
    });
  });

  describe("SMART-only surfaces", () => {
    it("answers 404 for /launch-context", async () => {
      const response = await postJson(stack, "/launch-context", {
        patient: "pat-1",
      });
      expect(response.status).toBe(404);
    });

    it("refuses the token exchange grant even with a ticket issuer row", async () => {
      await withTenantScope(stack.context.db, stack.scope, (bound) =>
        upsertEndpointTicketIssuer(bound, {
          issuer: "https://tickets.test",
          jwksUri: "https://tickets.test/jwks",
          acceptedTicketTypes: ["patient-self-access"],
          maxTokenLifetimeSecs: 300,
        }),
      );
      const response = await postForm(
        stack,
        "/token",
        {
          grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
          subject_token: "anything",
          subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
        },
        { authorization: basicAuth(stack.symmetricClient.clientId) },
      );
      expect(response.status).toBe(400);
      expect(((await response.json()) as TokenResponseBody).error).toBe(
        "unsupported_grant_type",
      );
    });
  });

  describe("the end-user surfaces", () => {
    it("tells the developer portal what kind of endpoint it is", async () => {
      const response = await stack.app.request(
        `${issuerPath(stack)}/apps/endpoint`,
      );
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ endpointKind: "oauth" });
    });

    it("tells the management page what kind of endpoint it is", async () => {
      const signIn = await stack.app.request(
        `${issuerPath(stack)}/manage/session`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            username: "clinician",
            password: TEST_PASSWORD,
          }),
        },
      );
      const cookie = (signIn.headers.get("set-cookie") ?? "").split(";", 1)[0];
      const response = await stack.app.request(
        `${issuerPath(stack)}/manage/authorizations`,
        { headers: { cookie: cookie ?? "" } },
      );
      expect(response.status).toBe(200);
      const body = (await response.json()) as { endpointKind: string };
      expect(body.endpointKind).toBe("oauth");
    });

    it("points an approved developer at the OpenID configuration", async () => {
      // The endpoint publishes no SMART configuration, so a portal pointing there
      // would hand the developer a 404.
      await expectServedDiscovery(
        stack,
        await portalDiscoveryUrls(stack),
        "openid-configuration",
      );
    });

    it("refuses a portal request with a launch URI or a scope that is not a scope-token", async () => {
      const withLaunch = await submitPortalRequest(stack, {
        launchUri: "https://portal-app.test/launch",
      });
      expect(withLaunch.status).toBe(400);
      expect(JSON.stringify(await withLaunch.json())).toContain("launchUri");

      const withBadScope = await submitPortalRequest(stack, {
        requestedScopes: ["openid", 'bad scope"'],
      });
      expect(withBadScope.status).toBe(400);
      expect(JSON.stringify(await withBadScope.json())).toContain(
        "requestedScopes.1",
      );
    });
  });

  describe("the admin API", () => {
    it("creates an OAuth endpoint with SMART off and the OAuth baseline", async () => {
      const cookie = await stack.signIn();
      const created = await adminJson<{
        endpoint: {
          kind: string;
          audience: string;
          smartConfigurationUrl: string | null;
          scopesSupported: string[];
          capabilities: Record<string, boolean>;
        };
      }>(stack, "POST", tenantPath(stack, "/endpoints"), {
        credential: { cookie },
        body: {
          slug: "orders-api",
          name: "Orders API",
          kind: "oauth",
          audience: "https://orders.test/api",
        },
        expect: 201,
      });
      expect(created.endpoint.kind).toBe("oauth");
      expect(created.endpoint.audience).toBe("https://orders.test/api");
      expect(created.endpoint.smartConfigurationUrl).toBeNull();
      expect(created.endpoint.scopesSupported).toEqual([
        ...OAUTH_DEFAULT_SCOPES_SUPPORTED,
      ]);
      expect(created.endpoint.capabilities["supportsEhrLaunch"]).toBe(false);
      expect(created.endpoint.capabilities["supportsStandaloneLaunch"]).toBe(
        false,
      );

      const smartConfiguration = await stack.app.request(
        `/t/${stack.tenant.slug}/e/orders-api/.well-known/smart-configuration`,
      );
      expect(smartConfiguration.status).toBe(404);

      const policies = await adminJson<{
        policies: { published: boolean; document: unknown }[];
      }>(stack, "GET", tenantPath(stack, "/endpoints/orders-api/policies"), {
        credential: { cookie },
      });
      expect(
        policies.policies.find((policy) => policy.published)?.document,
      ).toEqual(OAUTH_BASELINE_PRESET);
    });

    it("refuses creating an OAuth endpoint with a SMART-only capability on", async () => {
      const cookie = await stack.signIn();
      const response = await adminRequest(
        stack,
        "POST",
        tenantPath(stack, "/endpoints"),
        {
          credential: { cookie },
          body: {
            slug: "launching-api",
            name: "Launching API",
            kind: "oauth",
            audience: "https://launching.test/api",
            supportsEhrLaunch: true,
          },
        },
      );
      expect(response.status).toBe(400);
    });

    it("keeps a user's email and refuses a fhirUser reference", async () => {
      const cookie = await stack.signIn();
      const created = await adminJson<{
        user: { email: string | null; emailVerified: boolean };
      }>(stack, "POST", endpointPath(stack, "/users"), {
        credential: { cookie },
        body: {
          username: "with-email",
          displayName: "With Email",
          password: TEST_PASSWORD,
          email: "with-email@signet.test",
          emailVerified: true,
        },
        expect: 201,
      });
      expect(created.user).toMatchObject({
        email: "with-email@signet.test",
        emailVerified: true,
      });

      const refused = await adminRequest(
        stack,
        "POST",
        endpointPath(stack, "/users"),
        {
          credential: { cookie },
          body: {
            username: "with-fhir-user",
            displayName: "With fhirUser",
            password: TEST_PASSWORD,
            fhirUserReference: "Practitioner/1",
          },
        },
      );
      expect(refused.status).toBe(400);
    });

    it("withdraws email_verified when the address changes unvouched", async () => {
      const cookie = await stack.signIn();
      const created = await adminJson<{ user: { id: string } }>(
        stack,
        "POST",
        endpointPath(stack, "/users"),
        {
          credential: { cookie },
          body: {
            username: "changing-email",
            displayName: "Changing Email",
            password: TEST_PASSWORD,
            email: "first@signet.test",
            emailVerified: true,
          },
          expect: 201,
        },
      );
      const userPath = endpointPath(stack, `/users/${created.user.id}`);
      const patch = async (body: unknown) =>
        await adminJson<{
          user: { email: string | null; emailVerified: boolean };
        }>(stack, "PATCH", userPath, { credential: { cookie }, body });

      // A display name edit says nothing about the address.
      expect((await patch({ displayName: "Renamed" })).user).toMatchObject({
        email: "first@signet.test",
        emailVerified: true,
      });
      // A new address the operator does not vouch for is not verified.
      expect((await patch({ email: "second@signet.test" })).user).toMatchObject(
        { email: "second@signet.test", emailVerified: false },
      );
      // One they do vouch for is.
      expect(
        (await patch({ email: "third@signet.test", emailVerified: true })).user,
      ).toMatchObject({ email: "third@signet.test", emailVerified: true });
      // And a cleared address takes the flag with it.
      expect((await patch({ email: null })).user).toMatchObject({
        email: null,
        emailVerified: false,
      });
    });

    it("refuses a client launch URI and an allowlist entry that is not a scope-token", async () => {
      const cookie = await stack.signIn();
      const create = async (body: Record<string, unknown>) =>
        await adminRequest(stack, "POST", endpointPath(stack, "/clients"), {
          credential: { cookie },
          body: {
            name: "Orders app",
            clientType: "public",
            redirectUris: ["https://orders-app.test/callback"],
            ...body,
          },
        });

      const withLaunch = await create({
        launchUri: "https://orders-app.test/launch",
      });
      expect(withLaunch.status).toBe(400);
      expect(JSON.stringify(await withLaunch.json())).toContain("launchUri");

      const withBadScope = await create({
        allowedScopes: ["orders:read", 'bad scope"'],
      });
      expect(withBadScope.status).toBe(400);
      expect(JSON.stringify(await withBadScope.json())).toContain(
        "allowedScopes.1",
      );

      const accepted = await create({
        clientId: "orders-app-ok",
        allowedScopes: ["openid", "orders:read"],
      });
      expect(accepted.status).toBe(201);

      const clientPath = endpointPath(stack, "/clients/orders-app-ok");
      for (const body of [
        { launchUri: "https://orders-app.test/launch" },
        { allowedScopes: ['bad scope"'] },
      ]) {
        const patched = await adminRequest(stack, "PATCH", clientPath, {
          credential: { cookie },
          body,
        });
        expect(patched.status).toBe(400);
      }
    });

    it("refuses a permission ticket issuer", async () => {
      const cookie = await stack.signIn();
      const response = await adminRequest(
        stack,
        "PUT",
        endpointPath(stack, "/trust/ticket-issuer"),
        {
          credential: { cookie },
          body: {
            issuer: "https://tickets.test",
            jwksUri: "https://tickets.test/jwks",
            acceptedTicketTypes: ["patient-self-access"],
            maxTokenLifetimeSecs: 300,
          },
        },
      );
      expect(response.status).toBe(400);
    });

    it("refuses a fhirUser claim mapping for an upstream provider", async () => {
      const cookie = await stack.signIn();
      const response = await adminRequest(
        stack,
        "PUT",
        endpointPath(stack, "/idp"),
        {
          credential: { cookie },
          body: {
            issuer: "https://idp.test",
            displayName: "Upstream",
            clientId: "signet",
            clientSecret: "upstream-secret",
            scopes: ["openid", "email"],
            claimMappings: { fhirUser: "fhir_user", email: "email" },
          },
        },
      );
      expect(response.status).toBe(400);
    });

    it("refuses turning on a SMART-only capability", async () => {
      const cookie = await stack.signIn();
      const response = await adminRequest(stack, "PATCH", endpointPath(stack), {
        credential: { cookie },
        body: { supportsEhrLaunch: true },
      });
      expect(response.status).toBe(400);
    });

    it("refuses changing the endpoint's kind", async () => {
      const cookie = await stack.signIn();
      const response = await adminRequest(stack, "PATCH", endpointPath(stack), {
        credential: { cookie },
        body: { kind: "smart" },
      });
      expect(response.status).toBe(400);
    });

    it("refuses a launch simulation", async () => {
      const cookie = await stack.signIn();
      const response = await adminRequest(
        stack,
        "POST",
        endpointPath(stack, "/launch"),
        {
          credential: { cookie },
          body: { clientId: stack.publicClient.clientId, patient: "pat-1" },
        },
      );
      expect(response.status).toBe(400);
    });
  });
});

describeWithDatabase("a SMART on FHIR endpoint, on the same questions", () => {
  let stack: TestStack;

  beforeAll(async () => {
    stack = await createTestStack({
      endpoint: { supportsDynamicRegistration: true },
    });
  });

  afterAll(async () => {
    await stack.close();
  });

  it("still requires aud at /authorize", async () => {
    const response = await authorize(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid fhirUser",
      challenge: (await pkcePair()).challenge,
      aud: null,
    });
    expect(redirectedError(response)).toBe("invalid_request");
  });

  it("tells the developer portal it is a SMART endpoint", async () => {
    const response = await stack.app.request(
      `${issuerPath(stack)}/apps/endpoint`,
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ endpointKind: "smart" });
  });

  it("points an approved developer at the SMART configuration", async () => {
    await expectServedDiscovery(
      stack,
      await portalDiscoveryUrls(stack),
      "smart-configuration",
    );
  });

  it("describes no scopes by rule at consent", async () => {
    const session = await startAuthorization(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid fhirUser",
      challenge: (await pkcePair()).challenge,
    });
    const view = (await (
      await login(stack, session, {
        username: "clinician",
        password: TEST_PASSWORD,
      })
    ).json()) as KindAwareInteraction;
    expect(view.endpointKind).toBe("smart");
    expect(view.scopeDescriptions).toEqual({});
  });
});

describeWithDatabase("an endpoint that takes no self-serve requests", () => {
  let stack: TestStack;

  beforeAll(async () => {
    stack = await createTestStack({
      kind: "oauth",
      endpoint: { supportsDynamicRegistration: false },
    });
  });

  afterAll(async () => {
    await stack.close();
  });

  it("answers 404 for the portal's endpoint view", async () => {
    const response = await stack.app.request(
      `${issuerPath(stack)}/apps/endpoint`,
    );
    expect(response.status).toBe(404);
  });
});
