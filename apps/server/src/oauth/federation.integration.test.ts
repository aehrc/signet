/**
 * Federation, against a real database and a real identity provider on a socket.
 *
 * The happy path is worth one test and the refusals are worth the rest, because
 * federation is where an authorization server is asked to believe another server's
 * account of who somebody is. Each of these is a way that belief can be misplaced:
 * a callback that belongs to no request, one replayed, an ID token minted for
 * another relying party, one carrying a nonce from a different sign-in, and a
 * userinfo document about a different person.
 *
 * Every one of them must end the same way - one refusal, nothing signed in - and
 * the assertions check the outcome rather than the message, because the message is
 * deliberately identical.
 *
 * Author: John Grimes
 */

import { listEndUsers } from "@signet/db";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { adminRequest, endpointPath, tenantPath } from "../test/adminApi.js";
import { issuerPath, pkcePair, startAuthorization } from "../test/flows.js";
import { createTestStack, testDatabaseUrl } from "../test/harness.js";
import { startUpstreamIdp, UPSTREAM_SUBJECT } from "../test/upstreamIdp.js";

import type { TestStack } from "../test/harness.js";
import type { UpstreamIdp, UpstreamIdpOptions } from "../test/upstreamIdp.js";

describe.skipIf(testDatabaseUrl === undefined)("upstream federation", () => {
  let stack: TestStack;
  let idp: UpstreamIdp;

  beforeAll(async () => {
    idp = await startUpstreamIdp();
    stack = await createTestStack({
      endpoint: { authMode: "oidc", consentMode: "auto" },
      allowPrivateOutboundFetches: true,
    });

    // Configured through the admin API rather than by inserting a row, so the suite
    // exercises the route an operator actually uses - including the secret being
    // encrypted on the way in.
    const cookie = await stack.signIn();
    const response = await adminRequest(
      stack,
      "PUT",
      `${endpointPath(stack)}/idp`,
      {
        credential: { cookie },
        body: {
          issuer: idp.issuer,
          displayName: "Test Hospital SSO",
          clientId: idp.clientId,
          clientSecret: "upstream-secret",
          scopes: ["openid", "profile"],
          claimMappings: {
            fhirUser: "fhir_user",
            roles: "groups",
            displayName: "name",
            attributes: ["department"],
          },
        },
      },
    );
    if (response.status !== 200) {
      throw new Error(
        `could not configure the provider: ${String(response.status)} ${await response.text()}`,
      );
    }
  });

  afterAll(async () => {
    await stack.close();
    await idp.close();
  });

  beforeEach(() => {
    idp.configure({
      idTokenClaims: {
        fhir_user: "Practitioner/upstream-1",
        groups: ["clinician"],
        name: "Dr Upstream",
        department: "Cardiology",
      },
    });
  });

  /** Starts an authorization and follows it to the provider, returning the state. */
  async function toProvider(): Promise<{
    readonly session: string;
    readonly state: string;
  }> {
    const session = await startAuthorization(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid fhirUser",
      challenge: (await pkcePair()).challenge,
    });
    const response = await stack.app.request(
      `${issuerPath(stack)}/federation/start?session=${session}`,
    );
    expect(response.status).toBe(302);
    const location = response.headers.get("location") ?? "";
    // Follow the redirect the way a browser would. The provider learns the nonce
    // from the authorization request, and a test that skipped this step would be
    // asserting against a provider nobody had actually talked to.
    await fetch(location);
    const state = new URL(location).searchParams.get("state");
    expect(state).not.toBeNull();
    return { session, state: state ?? "" };
  }

  /** Presents a callback and returns the response. */
  async function callback(
    query: Readonly<Record<string, string>>,
  ): Promise<Response> {
    return await stack.app.request(
      `${issuerPath(stack)}/federation/callback?${new URLSearchParams(query).toString()}`,
    );
  }

  /** Runs a whole round trip, with the provider configured as given. */
  async function roundTrip(options?: UpstreamIdpOptions): Promise<Response> {
    const started = await toProvider();
    if (options !== undefined) {
      idp.configure(options);
    }
    return await callback({ state: started.state, code: "upstream-code" });
  }

  it("sends the browser to the provider with state, nonce and a challenge", async () => {
    const session = await startAuthorization(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid fhirUser",
      challenge: (await pkcePair()).challenge,
    });
    const response = await stack.app.request(
      `${issuerPath(stack)}/federation/start?session=${session}`,
    );

    expect(response.status).toBe(302);
    const url = new URL(response.headers.get("location") ?? "");
    expect(url.origin).toBe(idp.issuer);
    expect(url.pathname).toBe("/authorize");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("client_id")).toBe(idp.clientId);
    expect(url.searchParams.get("redirect_uri")).toBe(
      `${stack.issuer}/federation/callback`,
    );
    expect(url.searchParams.get("scope")).toBe("openid profile");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect((url.searchParams.get("state") ?? "").length).toBeGreaterThan(20);
    expect((url.searchParams.get("nonce") ?? "").length).toBeGreaterThan(20);
    expect(
      (url.searchParams.get("code_challenge") ?? "").length,
    ).toBeGreaterThan(20);
  });

  it("completes the authorization and provisions the account", async () => {
    const response = await roundTrip();

    // Consent mode is `auto` and no context is required, so the sign-in completes
    // the authorization outright: the redirect goes to the app, with a code.
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location") ?? "");
    expect(location.origin + location.pathname).toBe(
      stack.publicClient.redirectUris[0],
    );
    expect(location.searchParams.get("code")).not.toBeNull();

    const users = await listEndUsers(stack.context.db, stack.scope);
    const federated = users.find(
      (user) => user.username === `${idp.issuer}#${UPSTREAM_SUBJECT}`,
    );
    expect(federated).toBeDefined();
    expect(federated?.displayName).toBe("Dr Upstream");
    expect(federated?.fhirUserReference).toBe("Practitioner/upstream-1");
    expect(federated?.roles).toEqual(["clinician"]);
    expect(federated?.attributes).toEqual({ department: "Cardiology" });
    // Never a password: a federated account authenticates upstream and nowhere
    // else, and a null hash is what makes the local sign-in path refuse it.
    expect(federated?.passwordHash).toBeNull();
    expect(federated?.isPersona).toBe(false);
  });

  it("sends the PKCE verifier and the client secret to the token endpoint", async () => {
    await roundTrip();
    const sent = idp.lastTokenRequest();
    expect(sent?.["grant_type"]).toBe("authorization_code");
    expect(sent?.["code"]).toBe("upstream-code");
    expect(sent?.["client_secret"]).toBe("upstream-secret");
    expect((sent?.["code_verifier"] ?? "").length).toBeGreaterThan(20);
  });

  it("refreshes the mapped fields on a second sign-in", async () => {
    await roundTrip();
    await roundTrip({
      idTokenClaims: {
        fhir_user: "Practitioner/upstream-2",
        groups: ["clinician", "researcher"],
        name: "Dr Upstream-Renamed",
      },
    });

    const users = await listEndUsers(stack.context.db, stack.scope);
    const matching = users.filter(
      (user) => user.username === `${idp.issuer}#${UPSTREAM_SUBJECT}`,
    );
    // One row, not two: the second sign-in found what the first created.
    expect(matching).toHaveLength(1);
    expect(matching[0]?.fhirUserReference).toBe("Practitioner/upstream-2");
    expect(matching[0]?.roles).toEqual(["clinician", "researcher"]);
    // A role revoked upstream is a role revoked here - the provider is the source
    // of truth, so the mapped fields are replaced rather than merged.
    expect(matching[0]?.attributes).toEqual({});
  });

  it("prefers userinfo over the ID token, and requires the subjects to match", async () => {
    await roundTrip({
      idTokenClaims: { name: "From the ID token" },
      userinfo: {
        name: "From userinfo",
        fhir_user: "Practitioner/from-userinfo",
      },
    });

    const users = await listEndUsers(stack.context.db, stack.scope);
    const federated = users.find(
      (user) => user.username === `${idp.issuer}#${UPSTREAM_SUBJECT}`,
    );
    expect(federated?.displayName).toBe("From userinfo");
    expect(federated?.fhirUserReference).toBe("Practitioner/from-userinfo");
  });

  it("refuses a userinfo response about a different person", async () => {
    const response = await roundTrip({
      userinfo: { sub: "somebody-else", name: "Not them" },
    });
    expect(response.status).toBe(400);
  });

  it("refuses a callback with a state nobody minted", async () => {
    const response = await callback({ state: "made-up", code: "x" });
    expect(response.status).toBe(400);
  });

  it("refuses a replayed callback", async () => {
    const started = await toProvider();
    const first = await callback({
      state: started.state,
      code: "upstream-code",
    });
    expect(first.status).toBe(302);

    const second = await callback({
      state: started.state,
      code: "upstream-code",
    });
    // The state is consumed by a conditional update, so the second attempt finds
    // nothing - which is the same answer as a state that never existed.
    expect(second.status).toBe(400);
  });

  it("refuses an ID token addressed to another client of the provider", async () => {
    const response = await roundTrip({
      idTokenClaims: { aud: "some-other-relying-party" },
    });
    expect(response.status).toBe(400);
  });

  it("refuses an ID token carrying a nonce from another sign-in", async () => {
    const response = await roundTrip({
      idTokenClaims: { nonce: "a-nonce-from-somewhere-else" },
    });
    expect(response.status).toBe(400);
  });

  it("refuses an ID token from another issuer", async () => {
    const response = await roundTrip({
      idTokenClaims: { iss: "https://not-this-provider.example.org" },
    });
    expect(response.status).toBe(400);
  });

  it("refuses when the provider will not redeem the code", async () => {
    const response = await roundTrip({ tokenStatus: 400 });
    expect(response.status).toBe(400);
  });

  it("refuses when the provider reports an error instead of a code", async () => {
    const started = await toProvider();
    const response = await callback({
      state: started.state,
      error: "access_denied",
    });
    expect(response.status).toBe(400);
  });

  it("records the failure in the audit trail, with the reason", async () => {
    await callback({ state: "made-up", code: "x" });

    const cookie = await stack.signIn();
    const events = await adminRequest(
      stack,
      "GET",
      tenantPath(stack, "/audit?action=end-user.login-failed"),
      { credential: { cookie } },
    );
    const body = (await events.json()) as {
      readonly events: readonly { readonly detail: Record<string, unknown> }[];
    };
    const federationFailures = body.events.filter(
      (event) => event.detail["surface"] === "federation",
    );
    expect(federationFailures.length).toBeGreaterThan(0);
    expect(federationFailures[0]?.detail["reason"]).toBe("state-not-claimable");
  });

  it("does not start a round trip for a session already signed into", async () => {
    const started = await toProvider();
    const completed = await callback({
      state: started.state,
      code: "upstream-code",
    });
    expect(completed.status).toBe(302);

    const again = await stack.app.request(
      `${issuerPath(stack)}/federation/start?session=${started.session}`,
    );
    expect(again.status).toBe(400);
  });

  it("tells the login page which provider to send people to", async () => {
    const session = await startAuthorization(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid fhirUser",
      challenge: (await pkcePair()).challenge,
    });
    const response = await stack.app.request(
      `${issuerPath(stack)}/interaction/${session}`,
    );
    const view = (await response.json()) as {
      readonly authMode: string;
      readonly federation?: { readonly name: string | null };
    };
    expect(view.authMode).toBe("oidc");
    expect(view.federation?.name).toBe("Test Hospital SSO");
  });

  it("never returns the upstream client secret", async () => {
    const cookie = await stack.signIn();
    const response = await adminRequest(
      stack,
      "GET",
      `${endpointPath(stack)}/idp`,
      { credential: { cookie } },
    );
    const body = await response.text();
    expect(body).not.toContain("upstream-secret");
    expect(JSON.parse(body)).toMatchObject({
      idp: {
        hasClientSecret: true,
        redirectUri: `${stack.issuer}/federation/callback`,
      },
    });
  });

  it("reports what the provider's discovery document says", async () => {
    const cookie = await stack.signIn();
    const response = await adminRequest(
      stack,
      "POST",
      `${endpointPath(stack)}/idp/check`,
      { credential: { cookie } },
    );
    expect(await response.json()).toMatchObject({
      ok: true,
      supportsPkce: true,
      metadata: { issuer: idp.issuer, tokenEndpoint: `${idp.issuer}/token` },
    });
  });
});

describe.skipIf(testDatabaseUrl === undefined)(
  "an endpoint with local accounts",
  () => {
    let stack: TestStack;

    beforeAll(async () => {
      stack = await createTestStack({ allowPrivateOutboundFetches: true });
    });

    afterAll(async () => {
      await stack.close();
    });

    it("does not federate, even with a session in hand", async () => {
      const session = await startAuthorization(stack, {
        clientId: stack.publicClient.clientId,
        scope: "openid fhirUser",
        challenge: (await pkcePair()).challenge,
      });
      const response = await stack.app.request(
        `${issuerPath(stack)}/federation/start?session=${session}`,
      );
      expect(response.status).toBe(400);
    });

    it("provisions nobody through a callback", async () => {
      const before = await listEndUsers(stack.context.db, stack.scope);
      const response = await stack.app.request(
        `${issuerPath(stack)}/federation/callback?state=anything&code=x`,
      );
      expect(response.status).toBe(400);
      const after = await listEndUsers(stack.context.db, stack.scope);
      expect(after).toHaveLength(before.length);
    });
  },
);

describe.skipIf(testDatabaseUrl === undefined)("the outbound guard", () => {
  let stack: TestStack;
  let idp: UpstreamIdp;

  beforeAll(async () => {
    idp = await startUpstreamIdp();
    // The default: the guard on, as in production.
    stack = await createTestStack({ endpoint: { authMode: "oidc" } });

    const cookie = await stack.signIn();
    await adminRequest(stack, "PUT", `${endpointPath(stack)}/idp`, {
      credential: { cookie },
      body: { issuer: idp.issuer, clientId: idp.clientId },
    });
  });

  afterAll(async () => {
    await stack.close();
    await idp.close();
  });

  it("refuses to fetch a provider on a loopback address", async () => {
    const session = await startAuthorization(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid fhirUser",
      challenge: (await pkcePair()).challenge,
    });
    const response = await stack.app.request(
      `${issuerPath(stack)}/federation/start?session=${session}`,
    );
    // Not a redirect: the discovery fetch never happened, so there is nowhere to
    // send the browser. This is the guard doing its job on a real address.
    expect(response.status).toBe(400);

    const users = await listEndUsers(stack.context.db, stack.scope);
    expect(users.some((user) => user.username.startsWith(idp.issuer))).toBe(
      false,
    );
  });

  it("says so when an operator checks the configuration", async () => {
    const cookie = await stack.signIn();
    const response = await adminRequest(
      stack,
      "POST",
      `${endpointPath(stack)}/idp/check`,
      { credential: { cookie } },
    );
    const body = (await response.json()) as {
      readonly ok: boolean;
      readonly problem: string;
    };
    expect(body.ok).toBe(false);
    // The whole point of the check route: the operator is told what is wrong
    // before somebody is standing at a login page waiting for it.
    expect(["insecure-scheme", "blocked-address"]).toContain(body.problem);
  });
});
