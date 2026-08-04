/**
 * The authorization endpoint against a real database.
 *
 * The unit suite covers every validation rule; what is asserted here is that the
 * endpoint records what it validated. A session that did not carry the PKCE
 * challenge, or that carried the request's `scope` rather than the validated one,
 * would pass every unit test and lose the whole point of having a session.
 *
 * Author: John Grimes
 */

import { getAuthorizationSession } from "@signet/db";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  authorize,
  interactionState,
  issuerPath,
  pkcePair,
  postJson,
  startAuthorization,
} from "../test/flows.js";
import { createTestStack, testDatabaseUrl } from "../test/harness.js";

import type { TestStack } from "../test/harness.js";

const describeWithDatabase =
  testDatabaseUrl === undefined ? describe.skip : describe;

describeWithDatabase("the authorization endpoint", () => {
  let stack: TestStack;
  let challenge: string;

  beforeAll(async () => {
    stack = await createTestStack();
    challenge = (await pkcePair()).challenge;
  }, 60_000);

  afterAll(async () => {
    await stack.close();
  });

  it("records the request and sends the browser to sign in", async () => {
    const response = await authorize(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid fhirUser launch/patient patient/Observation.rs",
      challenge,
      state: "opaque-state",
      nonce: "n-1",
    });

    expect(response.status).toBe(302);
    const location = response.headers.get("location") ?? "";
    expect(location.startsWith(`${stack.issuer}/login?`)).toBe(true);

    const sessionId = new URL(location).searchParams.get("session") ?? "";
    const session = await getAuthorizationSession(
      stack.context.db,
      stack.scope,
      sessionId,
    );

    // Everything security-bearing is on the row, and nothing is left for a later
    // step to take from the browser.
    expect(session).toMatchObject({
      redirectUri: "https://app.test/cb",
      state: "opaque-state",
      nonce: "n-1",
      codeChallenge: challenge,
      codeChallengeMethod: "S256",
      aud: stack.endpoint.fhirBaseUrl,
      endUserId: null,
      consentGrantedAt: null,
      resolvedContext: null,
    });
    expect(session?.requestedScopes).toEqual([
      "openid",
      "fhirUser",
      "launch/patient",
      "patient/Observation.rs",
    ]);
  });

  it("accepts the same request as a form POST", async () => {
    const response = await authorize(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid",
      challenge,
      method: "POST",
    });
    expect(response.status).toBe(302);
  });

  it("refuses an unknown client without redirecting", async () => {
    const response = await authorize(stack, {
      clientId: "no-such-client",
      scope: "openid",
      challenge,
    });
    expect(response.status).toBe(400);
    expect(response.headers.get("location")).toBeNull();
  });

  it("refuses an unregistered redirect URI without redirecting to it", async () => {
    const response = await authorize(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid",
      challenge,
      redirectUri: "https://attacker.test/cb",
    });
    expect(response.status).toBe(400);
    expect(response.headers.get("location")).toBeNull();
  });

  it("delivers a scope refusal to the registered redirect URI", async () => {
    const response = await authorize(stack, {
      clientId: stack.publicClient.clientId,
      scope: "patient/Observation.zz",
      challenge,
      state: "st",
    });

    expect(response.status).toBe(302);
    const url = new URL(response.headers.get("location") ?? "");
    expect(url.origin + url.pathname).toBe("https://app.test/cb");
    expect(url.searchParams.get("error")).toBe("invalid_scope");
    expect(url.searchParams.get("state")).toBe("st");
  });

  it("refuses a request with no PKCE challenge", async () => {
    const response = await stack.app.request(
      `${issuerPath(stack)}/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: stack.publicClient.clientId,
        redirect_uri: "https://app.test/cb",
        scope: "openid",
        aud: stack.endpoint.fhirBaseUrl,
      }).toString()}`,
    );
    const url = new URL(response.headers.get("location") ?? "");
    expect(url.searchParams.get("error")).toBe("invalid_request");
    expect(url.searchParams.get("error_description")).toContain("PKCE");
  });

  it("refuses another FHIR server's aud", async () => {
    const response = await authorize(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid",
      challenge,
      aud: "https://fhir.attacker.test/R4",
    });
    const url = new URL(response.headers.get("location") ?? "");
    expect(url.searchParams.get("error")).toBe("invalid_request");
  });

  it("refuses a suspended client", async () => {
    const { setClientStatus, resolveClientScope } = await import("@signet/db");
    const resolved = await resolveClientScope(
      stack.context.db,
      stack.scope,
      stack.symmetricClient.clientId,
    );
    await setClientStatus(stack.context.db, resolved!.scope, "suspended");
    try {
      const response = await authorize(stack, {
        clientId: stack.symmetricClient.clientId,
        scope: "openid",
        challenge,
      });
      const url = new URL(response.headers.get("location") ?? "");
      expect(url.searchParams.get("error")).toBe("unauthorized_client");
    } finally {
      await setClientStatus(stack.context.db, resolved!.scope, "active");
    }
  });

  it("audits both the request and the refusal", async () => {
    const { queryAuditEvents } = await import("@signet/db");
    await authorize(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid",
      challenge,
    });
    await authorize(stack, {
      clientId: stack.publicClient.clientId,
      scope: "not-a-scope",
      challenge,
    });

    const page = await queryAuditEvents(stack.context.db, {
      tenantId: stack.tenant.id,
      actions: ["authorize.requested", "authorize.denied"],
    });
    const actions = page.events.map((event) => event.action);
    expect(actions).toContain("authorize.requested");
    expect(actions).toContain("authorize.denied");
  });
});

describeWithDatabase("the EHR launch", () => {
  let stack: TestStack;

  beforeAll(async () => {
    stack = await createTestStack();
  }, 60_000);

  afterAll(async () => {
    await stack.close();
  });

  /** Mints a launch handle the way an EHR does, through the public API. */
  async function mintHandle(context: Record<string, unknown>): Promise<string> {
    const response = await postJson(stack, "/launch-context", {
      ...context,
      forClientId: stack.publicClient.clientId,
      client_id: stack.symmetricClient.clientId,
      client_secret: "s3cret-value-for-tests",
    });
    expect(response.status).toBe(201);
    return ((await response.json()) as { launch: string }).launch;
  }

  it("mints a handle, resolves its context, and consumes it exactly once", async () => {
    const handle = await mintHandle({ patient: "pat-77", encounter: "enc-5" });
    const pkce = await pkcePair();

    const sessionId = await startAuthorization(stack, {
      clientId: stack.publicClient.clientId,
      scope: "launch openid patient/Observation.rs",
      challenge: pkce.challenge,
      launch: handle,
    });

    const state = await interactionState(stack, sessionId);
    // The context arrived with the handle, so no picker is needed: the step is login
    // and, once past it, consent.
    expect(state.step).toBe("login");

    const { getAuthorizationSession } = await import("@signet/db");
    const session = await getAuthorizationSession(
      stack.context.db,
      stack.scope,
      sessionId,
    );
    expect(session?.resolvedContext).toEqual({
      patient: "pat-77",
      encounter: "enc-5",
    });
    expect(session?.launchContextId).not.toBeNull();

    // The handle is single-use, so a second authorization with it must fail.
    const replay = await authorize(stack, {
      clientId: stack.publicClient.clientId,
      scope: "launch openid",
      challenge: pkce.challenge,
      launch: handle,
    });
    const url = new URL(replay.headers.get("location") ?? "");
    expect(url.searchParams.get("error")).toBe("invalid_request");
    expect(url.searchParams.get("error_description")).toContain(
      "already been used",
    );
  });

  it("refuses a handle bound to a different app", async () => {
    const handle = await mintHandle({ patient: "pat-88" });
    const response = await authorize(stack, {
      clientId: stack.symmetricClient.clientId,
      scope: "launch openid",
      challenge: (await pkcePair()).challenge,
      launch: handle,
    });
    const url = new URL(response.headers.get("location") ?? "");
    expect(url.searchParams.get("error_description")).toContain(
      "different app",
    );
  });

  it("refuses an unknown handle", async () => {
    const response = await authorize(stack, {
      clientId: stack.publicClient.clientId,
      scope: "launch openid",
      challenge: (await pkcePair()).challenge,
      launch: "not-a-real-handle",
    });
    const url = new URL(response.headers.get("location") ?? "");
    expect(url.searchParams.get("error_description")).toContain(
      "does not name a known launch context",
    );
  });

  it("refuses to mint a handle for an unauthenticated caller", async () => {
    const response = await postJson(stack, "/launch-context", {
      patient: "pat-1",
    });
    expect(response.status).toBe(400);
  });

  it("refuses a launch context that is not valid", async () => {
    const response = await postJson(stack, "/launch-context", {
      // `Patient` is not permitted in `fhirContext` with the default `launch` role.
      fhirContext: [{ reference: "Patient/pat-1" }],
      client_id: stack.symmetricClient.clientId,
      client_secret: "s3cret-value-for-tests",
    });
    expect(response.status).toBe(400);
  });
});
