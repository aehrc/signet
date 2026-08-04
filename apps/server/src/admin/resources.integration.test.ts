/**
 * The admin API's resource routes, against a real database.
 *
 * The properties worth asserting here are the ones a unit test cannot reach: that a
 * created endpoint can actually issue a token, that a secret appears exactly once and
 * never again, that suspending a client revokes what it already holds, that a
 * simulation agrees with the issuer, and that every write leaves an audit event
 * naming the principal that made it.
 *
 * Role enforcement is exercised through personal access tokens, since a token's role
 * is settable per test without touching anybody's membership.
 *
 * Author: John Grimes
 */

import {
  getActiveEndpointKey,
  listPolicyVersions,
  withTenantScope,
} from "@signet/db";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  adminJson,
  adminRequest,
  endpointPath,
  tenantPath,
} from "../test/adminApi.js";
import { createTestStack, testDatabaseUrl } from "../test/harness.js";

import type { AdminCredential } from "../test/adminApi.js";
import type { TestStack } from "../test/harness.js";

describe.skipIf(testDatabaseUrl === undefined)(
  "the admin API resource routes",
  () => {
    let stack: TestStack;
    let owner: AdminCredential;

    beforeAll(async () => {
      stack = await createTestStack();
      owner = { cookie: await stack.signIn() };
    });

    afterAll(async () => {
      await stack.close();
    });

    describe("endpoints", () => {
      it("lists the tenant's endpoints with their issuer", async () => {
        const body = await adminJson<{
          endpoints: { slug: string; issuer: string; capabilities: unknown }[];
        }>(stack, "GET", tenantPath(stack, "/endpoints"), {
          credential: owner,
        });

        const endpoint = body.endpoints.find(
          (candidate) => candidate.slug === stack.endpoint.slug,
        );
        expect(endpoint?.issuer).toBe(stack.issuer);
        expect(endpoint?.capabilities).toBeDefined();
      });

      it("creates an endpoint that can immediately serve discovery and sign", async () => {
        const created = await adminJson<{
          endpoint: { slug: string; issuer: string };
        }>(stack, "POST", tenantPath(stack, "/endpoints"), {
          credential: owner,
          body: {
            slug: "second",
            name: "Second endpoint",
            fhirBaseUrl: "https://other.test/fhir",
          },
          expect: 201,
        });

        // Discovery answers, which means the row, the key and the policy all exist.
        const discovery = await stack.app.request(
          `/t/${stack.tenant.slug}/e/second/.well-known/smart-configuration`,
        );
        expect(discovery.status).toBe(200);

        const jwks = (await (
          await stack.app.request(`/t/${stack.tenant.slug}/e/second/jwks`)
        ).json()) as { keys: unknown[] };
        expect(jwks.keys.length).toBeGreaterThan(0);

        const policies = await adminJson<{
          policies: { published: boolean }[];
        }>(stack, "GET", tenantPath(stack, "/endpoints/second/policies"), {
          credential: owner,
        });
        expect(policies.policies.some((policy) => policy.published)).toBe(true);
        expect(created.endpoint.issuer).toContain("/e/second");
      });

      it("refuses a duplicate slug with a conflict rather than a 500", async () => {
        const response = await adminRequest(
          stack,
          "POST",
          tenantPath(stack, "/endpoints"),
          {
            credential: owner,
            body: {
              slug: stack.endpoint.slug,
              name: "Clash",
              fhirBaseUrl: "https://clash.test/fhir",
            },
          },
        );
        expect(response.status).toBe(409);
      });

      it("changes a capability flag and the discovery document with it", async () => {
        const before = (await (
          await stack.app.request(
            `${endpointPathPublic(stack)}/.well-known/smart-configuration`,
          )
        ).json()) as { capabilities: string[] };
        expect(before.capabilities).toContain("authorize-post");

        await adminJson(stack, "PATCH", endpointPath(stack), {
          credential: owner,
          body: { supportsAuthorizePost: false },
        });

        const after = (await (
          await stack.app.request(
            `${endpointPathPublic(stack)}/.well-known/smart-configuration`,
          )
        ).json()) as { capabilities: string[] };
        expect(after.capabilities).not.toContain("authorize-post");

        // Restored, since the rest of this suite shares the endpoint.
        await adminJson(stack, "PATCH", endpointPath(stack), {
          credential: owner,
          body: { supportsAuthorizePost: true },
        });
      });

      it("records who changed what", async () => {
        await adminJson(stack, "PATCH", endpointPath(stack), {
          credential: owner,
          body: { description: "Edited by the suite" },
        });

        const audit = await adminJson<{
          events: { action: string; actorType: string; actorId: string }[];
        }>(stack, "GET", tenantPath(stack, "/audit?action=endpoint.updated"), {
          credential: owner,
        });

        const event = audit.events[0];
        expect(event?.action).toBe("endpoint.updated");
        expect(event?.actorType).toBe("admin-user");
        expect(event?.actorId).toBe(stack.admin.id);
      });

      it("refuses to let a developer change configuration", async () => {
        const developer = { bearer: await stack.mintApiToken("developer") };
        const response = await adminRequest(
          stack,
          "PATCH",
          endpointPath(stack),
          { credential: developer, body: { name: "Nope" } },
        );
        expect(response.status).toBe(403);
      });
    });

    describe("signing keys", () => {
      it("adds a key as next, publishes it, and only signs with it once promoted", async () => {
        const activeBefore = await withTenantScope(
          stack.context.db,
          stack.scope,
          (bound) => getActiveEndpointKey(bound),
        );

        const created = await adminJson<{
          key: { kid: string; status: string };
        }>(stack, "POST", endpointPath(stack, "/keys"), {
          credential: owner,
          body: { algorithm: "RS384" },
          expect: 201,
        });
        expect(created.key.status).toBe("next");

        // Published before promotion, so relying parties can cache it.
        const jwks = (await (
          await stack.app.request(`${endpointPathPublic(stack)}/jwks`)
        ).json()) as { keys: { kid: string }[] };
        expect(jwks.keys.map((key) => key.kid)).toContain(created.key.kid);

        // Still not the signing key.
        const stillActive = await withTenantScope(
          stack.context.db,
          stack.scope,
          (bound) => getActiveEndpointKey(bound),
        );
        expect(stillActive?.kid).toBe(activeBefore?.kid);

        const promoted = await adminJson<{ key: { kid: string } }>(
          stack,
          "POST",
          endpointPath(stack, "/keys/promote"),
          { credential: owner },
        );
        expect(promoted.key.kid).toBe(created.key.kid);

        const nowActive = await withTenantScope(
          stack.context.db,
          stack.scope,
          (bound) => getActiveEndpointKey(bound),
        );
        expect(nowActive?.kid).toBe(created.key.kid);
      });

      it("never returns private key material", async () => {
        const body = await adminJson<{ keys: Record<string, unknown>[] }>(
          stack,
          "GET",
          endpointPath(stack, "/keys"),
          { credential: owner },
        );

        for (const key of body.keys) {
          expect(Object.keys(key)).not.toContain("privateJwkEncrypted");
          // Nor the private half of the JWK itself.
          expect(JSON.stringify(key)).not.toContain('"d"');
        }
      });

      it("refuses to promote when there is nothing to promote", async () => {
        const response = await adminRequest(
          stack,
          "POST",
          endpointPath(stack, "/keys/promote"),
          { credential: owner },
        );
        expect(response.status).toBe(409);
      });
    });

    describe("clients", () => {
      it("returns a generated secret exactly once", async () => {
        const created = await adminJson<{
          client: { clientId: string; hasSecret: boolean };
          secret: string;
        }>(stack, "POST", endpointPath(stack, "/clients"), {
          credential: owner,
          body: {
            name: "Secret App",
            clientType: "confidential-symmetric",
            redirectUris: ["https://secret.test/cb"],
            grantTypes: ["authorization_code"],
            allowedScopes: ["openid", "patient/*.rs"],
          },
          expect: 201,
        });

        expect(created.secret.length).toBeGreaterThan(20);
        expect(created.client.hasSecret).toBe(true);

        const read = await adminJson<{ client: Record<string, unknown> }>(
          stack,
          "GET",
          endpointPath(stack, `/clients/${created.client.clientId}`),
          { credential: owner },
        );
        expect(read.client["secret"]).toBeUndefined();
        expect(read.client["secretHash"]).toBeUndefined();
        expect(read.client["hasSecret"]).toBe(true);
      });

      it("derives a readable client identifier from the name", async () => {
        const created = await adminJson<{ client: { clientId: string } }>(
          stack,
          "POST",
          endpointPath(stack, "/clients"),
          {
            credential: owner,
            body: { name: "Growth Chart App", clientType: "public" },
            expect: 201,
          },
        );
        expect(created.client.clientId).toMatch(/^growth-chart-app-[a-z0-9]+$/);
      });

      it("refuses a client type the endpoint does not allow", async () => {
        const restricted = await createTestStack({
          endpoint: { allowsPublicClients: false },
        });
        try {
          const credential = { cookie: await restricted.signIn() };
          const response = await adminRequest(
            restricted,
            "POST",
            endpointPath(restricted, "/clients"),
            {
              credential,
              body: { name: "Public app", clientType: "public" },
            },
          );
          expect(response.status).toBe(400);
        } finally {
          await restricted.close();
        }
      });

      it("refuses an asymmetric client with no keys to verify against", async () => {
        const response = await adminRequest(
          stack,
          "POST",
          endpointPath(stack, "/clients"),
          {
            credential: owner,
            body: {
              name: "Keyless",
              clientType: "confidential-asymmetric",
            },
          },
        );
        expect(response.status).toBe(400);
        const body = (await response.json()) as {
          issues: { path: string }[];
        };
        expect(body.issues.map((issue) => issue.path)).toContain("jwks");
      });

      it("rotates a secret, invalidating the previous one", async () => {
        const created = await adminJson<{
          client: { clientId: string };
          secret: string;
        }>(stack, "POST", endpointPath(stack, "/clients"), {
          credential: owner,
          body: {
            name: "Rotating App",
            clientType: "confidential-symmetric",
            grantTypes: ["client_credentials"],
            allowedScopes: ["system/*.rs"],
          },
          expect: 201,
        });

        const rotated = await adminJson<{ secret: string }>(
          stack,
          "POST",
          endpointPath(stack, `/clients/${created.client.clientId}/secret`),
          { credential: owner },
        );
        expect(rotated.secret).not.toBe(created.secret);

        // The old secret no longer authenticates at the token endpoint.
        const refused = await stack.app.request(
          `${endpointPathPublic(stack)}/token`,
          {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              grant_type: "client_credentials",
              scope: "system/Observation.rs",
              client_id: created.client.clientId,
              client_secret: created.secret,
            }).toString(),
          },
        );
        expect(refused.status).toBe(401);
      });

      it("refuses to rotate a secret a client cannot hold", async () => {
        const response = await adminRequest(
          stack,
          "POST",
          endpointPath(stack, `/clients/${stack.publicClient.clientId}/secret`),
          { credential: owner },
        );
        expect(response.status).toBe(400);
      });

      it("revokes live tokens when a client is suspended", async () => {
        const tokenResponse = await stack.app.request(
          `${endpointPathPublic(stack)}/token`,
          {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              grant_type: "client_credentials",
              scope: "system/Observation.rs",
              client_id: stack.symmetricClient.clientId,
              client_secret: "s3cret-value-for-tests",
            }).toString(),
          },
        );
        // The fixture symmetric client is not registered for client_credentials, so
        // this suspension test uses a client of its own.
        expect([200, 400]).toContain(tokenResponse.status);

        const created = await adminJson<{
          client: { clientId: string };
          secret: string;
        }>(stack, "POST", endpointPath(stack, "/clients"), {
          credential: owner,
          body: {
            name: "Suspendable App",
            clientType: "confidential-symmetric",
            grantTypes: ["client_credentials"],
            allowedScopes: ["system/*.rs"],
          },
          expect: 201,
        });

        const issued = (await (
          await stack.app.request(`${endpointPathPublic(stack)}/token`, {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              grant_type: "client_credentials",
              scope: "system/Observation.rs",
              client_id: created.client.clientId,
              client_secret: created.secret,
            }).toString(),
          })
        ).json()) as { access_token: string };
        expect(issued.access_token).toBeDefined();

        await adminJson(
          stack,
          "PATCH",
          endpointPath(stack, `/clients/${created.client.clientId}`),
          { credential: owner, body: { status: "suspended" } },
        );

        const introspection = (await (
          await stack.app.request(`${endpointPathPublic(stack)}/introspect`, {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              token: issued.access_token,
              client_id: stack.publicClient.clientId,
            }).toString(),
          })
        ).json()) as { active: boolean };
        expect(introspection.active).toBe(false);
      });

      it("lets a viewer read but not write", async () => {
        const viewer = { bearer: await stack.mintApiToken("viewer") };

        const read = await adminRequest(
          stack,
          "GET",
          endpointPath(stack, "/clients"),
          { credential: viewer },
        );
        expect(read.status).toBe(200);

        const write = await adminRequest(
          stack,
          "POST",
          endpointPath(stack, "/clients"),
          {
            credential: viewer,
            body: { name: "Nope", clientType: "public" },
          },
        );
        expect(write.status).toBe(403);
      });
    });

    describe("policies", () => {
      it("creates a version without publishing it", async () => {
        const before = await listPolicyVersions(stack.context.db, stack.scope);

        const created = await adminJson<{
          policy: { version: number; published: boolean };
        }>(stack, "POST", endpointPath(stack, "/policies"), {
          credential: owner,
          body: {
            note: "Draft",
            document: {
              version: 1,
              scopeGrants: [{ match: "patient/*.rs", allow: true }],
              claimRules: [],
              contextRules: [],
              defaults: { accessTokenTtl: 300, refreshTokenTtl: 3600 },
            },
          },
          expect: 201,
        });

        expect(created.policy.published).toBe(false);
        expect(created.policy.version).toBeGreaterThan(
          before.at(0)?.version ?? 0,
        );
      });

      it("refuses a document the evaluator would refuse", async () => {
        const response = await adminRequest(
          stack,
          "POST",
          endpointPath(stack, "/policies"),
          {
            credential: owner,
            body: {
              document: {
                version: 1,
                scopeGrants: [{ match: "patient/*.rs", allow: true }],
                claimRules: [
                  { when: { always: true }, emit: { a: "{{ user.fhirUser" } },
                ],
                contextRules: [],
                defaults: { accessTokenTtl: 300, refreshTokenTtl: 3600 },
              },
            },
          },
        );

        expect(response.status).toBe(400);
        const body = (await response.json()) as { issues: { path: string }[] };
        expect(body.issues[0]?.path).toContain("claimRules");
      });

      it("publishes and rolls back by publishing again", async () => {
        const versions = await adminJson<{
          policies: { version: number; published: boolean }[];
        }>(stack, "GET", endpointPath(stack, "/policies"), {
          credential: owner,
        });
        const live = versions.policies.find((policy) => policy.published);
        const other = versions.policies.find((policy) => !policy.published);
        expect(live).toBeDefined();
        expect(other).toBeDefined();

        await adminJson(
          stack,
          "POST",
          endpointPath(stack, `/policies/${String(other?.version)}/publish`),
          { credential: owner },
        );

        const after = await adminJson<{
          policies: { version: number; published: boolean }[];
        }>(stack, "GET", endpointPath(stack, "/policies"), {
          credential: owner,
        });
        // Exactly one published version, always: the database enforces it.
        expect(
          after.policies.filter((policy) => policy.published),
        ).toHaveLength(1);

        await adminJson(
          stack,
          "POST",
          endpointPath(stack, `/policies/${String(live?.version)}/publish`),
          { credential: owner },
        );
      });

      it("simulates an unsaved document without storing it", async () => {
        const versionsBefore = await listPolicyVersions(
          stack.context.db,
          stack.scope,
        );

        const result = await adminJson<{
          scope: string;
          accessTokenClaims: Record<string, unknown>;
          denied: { reason: string }[];
        }>(stack, "POST", endpointPath(stack, "/policies/simulate"), {
          credential: owner,
          body: {
            clientId: stack.publicClient.clientId,
            endUserId: stack.user.id,
            requestedScopes: "patient/Observation.rs patient/Condition.cud",
            context: { patient: "pat-1" },
            document: {
              version: 1,
              scopeGrants: [
                {
                  match: "patient/*.rs",
                  allow: true,
                  requireContext: ["patient"],
                },
              ],
              claimRules: [
                {
                  when: { always: true },
                  emit: { authorities: ["read:{{ context.patient }}"] },
                },
              ],
              contextRules: [],
              defaults: { accessTokenTtl: 120, refreshTokenTtl: 3600 },
            },
          },
        });

        expect(result.scope).toBe("patient/Observation.rs");
        expect(result.accessTokenClaims["authorities"]).toEqual(["read:pat-1"]);
        expect(result.denied.length).toBeGreaterThan(0);

        const versionsAfter = await listPolicyVersions(
          stack.context.db,
          stack.scope,
        );
        expect(versionsAfter).toHaveLength(versionsBefore.length);
      });

      it("agrees with what the token endpoint actually issues", async () => {
        // The claim worth making about the simulator, and the only one that matters:
        // simulate and issue over the same inputs, then compare.
        const simulated = await adminJson<{
          accessTokenClaims: Record<string, unknown>;
        }>(stack, "POST", endpointPath(stack, "/policies/simulate"), {
          credential: owner,
          body: {
            clientId: stack.backendClient.client.clientId,
            requestedScopes: "system/Observation.rs",
            grantType: "client_credentials",
          },
        });

        const { backendToken, decodePayload } =
          await import("../test/flows.js");
        const issued = (await (
          await backendToken(stack, "system/Observation.rs")
        ).json()) as { access_token: string };
        const actual = decodePayload(issued.access_token);

        expect(actual["scope"]).toBe(simulated.accessTokenClaims["scope"]);
        expect(actual["aud"]).toBe(simulated.accessTokenClaims["aud"]);
        expect(actual["iss"]).toBe(simulated.accessTokenClaims["iss"]);
        expect(actual["client_id"]).toBe(
          simulated.accessTokenClaims["client_id"],
        );
      });

      it("reports scopes it could not parse rather than dropping them", async () => {
        const result = await adminJson<{
          rejectedScopes: { raw: string }[];
        }>(stack, "POST", endpointPath(stack, "/policies/simulate"), {
          credential: owner,
          body: {
            clientId: stack.publicClient.clientId,
            requestedScopes: "patient/Observation.sr",
          },
        });

        expect(result.rejectedScopes[0]?.raw).toBe("patient/Observation.sr");
      });
    });

    describe("end users", () => {
      it("creates a persona with a seeded context and no password", async () => {
        const created = await adminJson<{
          user: { id: string; isPersona: boolean; hasPassword: boolean };
        }>(stack, "POST", endpointPath(stack, "/users"), {
          credential: owner,
          body: {
            username: "persona-two",
            displayName: "Second Persona",
            isPersona: true,
            fhirUserReference: "Patient/pat-7",
            defaultContext: { patient: "pat-7" },
          },
          expect: 201,
        });

        expect(created.user.isPersona).toBe(true);
        expect(created.user.hasPassword).toBe(false);
      });

      it("refuses a password for a persona", async () => {
        const response = await adminRequest(
          stack,
          "POST",
          endpointPath(stack, "/users"),
          {
            credential: owner,
            body: {
              username: "persona-three",
              displayName: "Third",
              isPersona: true,
              password: "a-password-here",
            },
          },
        );
        expect(response.status).toBe(400);
      });

      it("never returns a password hash", async () => {
        const body = await adminJson<{ users: Record<string, unknown>[] }>(
          stack,
          "GET",
          endpointPath(stack, "/users"),
          { credential: owner },
        );

        for (const user of body.users) {
          expect(Object.keys(user)).not.toContain("passwordHash");
        }
      });

      it("disables a user, and the disabled user can no longer sign in", async () => {
        const created = await adminJson<{ user: { id: string } }>(
          stack,
          "POST",
          endpointPath(stack, "/users"),
          {
            credential: owner,
            body: {
              username: "temp-clinician",
              displayName: "Temporary",
              password: "temporary-password",
            },
            expect: 201,
          },
        );

        await adminJson(
          stack,
          "PATCH",
          endpointPath(stack, `/users/${created.user.id}`),
          { credential: owner, body: { disabled: true } },
        );

        const { authorize, pkcePair, startAuthorization, login } =
          await import("../test/flows.js");
        void authorize;
        const pkce = await pkcePair("disabled-user-check");
        const session = await startAuthorization(stack, {
          clientId: stack.publicClient.clientId,
          scope: "openid",
          challenge: pkce.challenge,
        });
        const refused = await login(stack, session, {
          username: "temp-clinician",
          password: "temporary-password",
        });
        expect(refused.status).toBe(401);
      });
    });

    describe("the launch simulator", () => {
      it("mints a redeemable handle and the URL to open the app at", async () => {
        const client = await adminJson<{ client: { clientId: string } }>(
          stack,
          "POST",
          endpointPath(stack, "/clients"),
          {
            credential: owner,
            body: {
              name: "Launchable App",
              clientType: "public",
              redirectUris: ["https://launchable.test/cb"],
              launchUri: "https://launchable.test/launch",
              grantTypes: ["authorization_code"],
              allowedScopes: ["openid", "launch", "patient/*.rs"],
            },
            expect: 201,
          },
        );

        const minted = await adminJson<{
          launch: string;
          iss: string;
          launchUrl: string;
        }>(stack, "POST", endpointPath(stack, "/launch"), {
          credential: owner,
          body: {
            clientId: client.client.clientId,
            patient: "pat-42",
          },
          expect: 201,
        });

        expect(minted.iss).toBe(stack.issuer);
        const launchUrl = new URL(minted.launchUrl);
        expect(launchUrl.searchParams.get("iss")).toBe(stack.issuer);
        expect(launchUrl.searchParams.get("launch")).toBe(minted.launch);

        // The handle is a real one: an authorization redeems it and inherits the
        // context, which is what makes the simulator worth having.
        const { authorizeToCode } = await import("../test/flows.js");
        const { code } = await authorizeToCode(stack, {
          clientId: client.client.clientId,
          scope: "launch patient/Observation.rs",
          redirectUri: "https://launchable.test/cb",
          launch: minted.launch,
        });
        expect(code).toBeDefined();
      });

      it("refuses to bind a handle to a client that is not registered here", async () => {
        const response = await adminRequest(
          stack,
          "POST",
          endpointPath(stack, "/launch"),
          { credential: owner, body: { clientId: "no-such-client" } },
        );
        expect(response.status).toBe(404);
      });
    });

    describe("the HAPI interceptor", () => {
      it("serves Java carrying this endpoint's issuer and keys", async () => {
        const response = await adminRequest(
          stack,
          "GET",
          endpointPath(stack, "/integrations/hapi-interceptor"),
          { credential: owner },
        );

        expect(response.status).toBe(200);
        expect(response.headers.get("content-type")).toContain("text/plain");
        const source = await response.text();
        expect(source).toContain(stack.issuer);
        expect(source).toContain(`${stack.issuer}/jwks`);
        expect(source).toContain(stack.endpoint.fhirBaseUrl);
      });
    });

    describe("membership and tokens", () => {
      it("refuses to grant a role above the caller's own", async () => {
        const admin = { bearer: await stack.mintApiToken("admin") };
        const response = await adminRequest(
          stack,
          "PUT",
          tenantPath(stack, "/members"),
          {
            credential: admin,
            body: { email: stack.outsider.email, role: "owner" },
          },
        );
        expect(response.status).toBe(403);
      });

      it("refuses to mint a token above the caller's own role", async () => {
        const admin = { bearer: await stack.mintApiToken("admin") };
        const response = await adminRequest(
          stack,
          "POST",
          tenantPath(stack, "/api-tokens"),
          { credential: admin, body: { name: "escalate", role: "owner" } },
        );
        expect(response.status).toBe(403);
      });

      it("refuses to leave the tenant without an owner", async () => {
        const response = await adminRequest(
          stack,
          "PUT",
          tenantPath(stack, "/members"),
          {
            credential: owner,
            body: { email: stack.admin.email, role: "viewer" },
          },
        );
        expect(response.status).toBe(409);
      });

      it("returns a new personal access token exactly once", async () => {
        const created = await adminJson<{
          token: { id: string };
          value: string;
        }>(stack, "POST", tenantPath(stack, "/api-tokens"), {
          credential: owner,
          body: { name: "suite token", role: "viewer" },
          expect: 201,
        });
        expect(created.value.length).toBeGreaterThan(20);

        const listed = await adminJson<{
          tokens: Record<string, unknown>[];
        }>(stack, "GET", tenantPath(stack, "/api-tokens"), {
          credential: owner,
        });
        const token = listed.tokens.find(
          (candidate) => candidate["id"] === created.token.id,
        );
        expect(token).toBeDefined();
        expect(Object.keys(token ?? {})).not.toContain("tokenHash");
      });

      it("revokes a token, and the revoked token stops working", async () => {
        const created = await adminJson<{
          token: { id: string };
          value: string;
        }>(stack, "POST", tenantPath(stack, "/api-tokens"), {
          credential: owner,
          body: { name: "doomed", role: "viewer" },
          expect: 201,
        });

        await adminRequest(
          stack,
          "DELETE",
          tenantPath(stack, `/api-tokens/${created.token.id}`),
          { credential: owner },
        );

        const after = await adminRequest(stack, "GET", tenantPath(stack), {
          credential: { bearer: created.value },
        });
        expect(after.status).toBe(401);
      });
    });

    describe("the audit browser", () => {
      it("pages with an opaque cursor", async () => {
        const first = await adminJson<{
          events: { id: string }[];
          nextCursor: string | null;
        }>(stack, "GET", tenantPath(stack, "/audit?limit=2"), {
          credential: owner,
        });
        expect(first.events).toHaveLength(2);
        expect(first.nextCursor).not.toBeNull();

        const second = await adminJson<{ events: { id: string }[] }>(
          stack,
          "GET",
          tenantPath(
            stack,
            `/audit?limit=2&cursor=${encodeURIComponent(String(first.nextCursor))}`,
          ),
          { credential: owner },
        );

        const firstIds = new Set(first.events.map((event) => event.id));
        for (const event of second.events) {
          expect(firstIds.has(event.id)).toBe(false);
        }
      });

      it("refuses a cursor it did not issue", async () => {
        const response = await adminRequest(
          stack,
          "GET",
          tenantPath(stack, "/audit?cursor=not-a-cursor"),
          { credential: owner },
        );
        expect(response.status).toBe(400);
      });

      it("refuses an action it does not record rather than matching nothing", async () => {
        const response = await adminRequest(
          stack,
          "GET",
          tenantPath(stack, "/audit?action=made.up"),
          { credential: owner },
        );
        expect(response.status).toBe(400);
      });

      it("resolves the description of each action server-side", async () => {
        const body = await adminJson<{
          events: { action: string; description: string | null }[];
        }>(stack, "GET", tenantPath(stack, "/audit?limit=5"), {
          credential: owner,
        });
        expect(body.events[0]?.description).toBeTruthy();
      });

      it("cannot be asked for another tenant's trail", async () => {
        const other = await createTestStack();
        try {
          // Even holding an owner token for the other tenant, the path decides
          // which trail is read, and the middleware refuses the mismatch.
          const response = await adminRequest(
            stack,
            "GET",
            tenantPath(stack, "/audit"),
            { credential: { bearer: await other.mintApiToken("owner") } },
          );
          expect(response.status).toBe(404);
        } finally {
          await other.close();
        }
      });
    });
  },
);

/** The public issuer path for the fixture endpoint, for non-admin requests. */
function endpointPathPublic(stack: TestStack): string {
  return `/t/${stack.tenant.slug}/e/${stack.endpoint.slug}`;
}
