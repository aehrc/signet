/**
 * Refresh, introspection, revocation and UserInfo, against a real database.
 *
 * The refresh suite is the one worth reading twice. Rotation is only useful if reuse
 * of a rotated token is detected, and detection is only useful if it revokes the
 * whole family — so both are asserted, along with the property that a client bug
 * (asking for a scope it does not hold) does *not* cost the user their session.
 */

import {
  findRefreshToken,
  hashToken,
  introspectAccessToken,
  listRefreshTokensForSubject,
  queryAuditEvents,
} from "@signet/db";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  authorizeToCode,
  basicAuth,
  decodePayload,
  issuerPath,
  postForm,
} from "../test/flows.js";
import { createTestStack, testDatabaseUrl } from "../test/harness.js";

import type { TestStack } from "../test/harness.js";

const describeWithDatabase =
  testDatabaseUrl === undefined ? describe.skip : describe;

/** A token response body, as far as these suites read it. */
interface TokenResponseBody {
  readonly access_token: string;
  readonly scope: string;
  readonly refresh_token?: string;
  readonly error?: string;
  readonly error_description?: string;
}

describeWithDatabase("the refresh_token grant", () => {
  let stack: TestStack;

  beforeAll(async () => {
    stack = await createTestStack();
  }, 60_000);

  afterAll(async () => {
    await stack.close();
  });

  /** Runs a full authorization for the confidential client and returns its tokens. */
  async function firstTokens(
    scope = "openid offline_access user/Observation.rs",
  ): Promise<TokenResponseBody> {
    const { code, verifier } = await authorizeToCode(stack, {
      clientId: stack.symmetricClient.clientId,
      scope,
    });
    const response = await postForm(
      stack,
      "/token",
      {
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://app.test/cb",
        code_verifier: verifier,
      },
      { authorization: basicAuth(stack.symmetricClient.clientId) },
    );
    return (await response.json()) as TokenResponseBody;
  }

  /** Presents a refresh token, optionally narrowing the scope. */
  async function refresh(
    refreshToken: string,
    scope?: string,
  ): Promise<Response> {
    return await postForm(
      stack,
      "/token",
      {
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        ...(scope === undefined ? {} : { scope }),
      },
      { authorization: basicAuth(stack.symmetricClient.clientId) },
    );
  }

  it("issues a new access token and a new refresh token", async () => {
    const first = await firstTokens();
    const response = await refresh(first.refresh_token as string);

    expect(response.status).toBe(200);
    const second = (await response.json()) as TokenResponseBody;
    expect(second.refresh_token).toBeDefined();
    expect(second.refresh_token).not.toBe(first.refresh_token);
    expect(second.scope).toBe(first.scope);
  });

  it("revokes the presented token, so it cannot be used twice", async () => {
    const first = await firstTokens();
    const presented = first.refresh_token as string;
    await refresh(presented);

    const row = await findRefreshToken(
      stack.context.db,
      stack.scope,
      await hashToken(presented),
    );
    expect(row?.revokedAt).not.toBeNull();
    expect(row?.replacedById).not.toBeNull();
  });

  it("narrows the granted scopes when asked", async () => {
    const first = await firstTokens();
    const second = (await (
      await refresh(first.refresh_token as string, "user/Observation.r")
    ).json()) as TokenResponseBody;

    expect(second.scope).toBe("user/Observation.r");
  });

  it("refuses to widen the granted scopes, without spending the token", async () => {
    const first = await firstTokens("openid offline_access user/Observation.r");
    const presented = first.refresh_token as string;

    const response = await refresh(presented, "user/Observation.cruds");
    expect(response.status).toBe(400);
    expect(((await response.json()) as TokenResponseBody).error).toBe(
      "invalid_scope",
    );

    // A client bug must not log the user out: the token is still usable.
    expect((await refresh(presented)).status).toBe(200);
  });

  it("detects reuse and revokes the whole family", async () => {
    const first = await firstTokens();
    const rotated = first.refresh_token as string;
    const second = (await (await refresh(rotated)).json()) as TokenResponseBody;

    // Presenting the rotated token means two parties hold it.
    const replay = await refresh(rotated);
    expect(replay.status).toBe(400);
    expect(((await replay.json()) as TokenResponseBody).error).toBe(
      "invalid_grant",
    );

    // The successor goes too, so the thief and the victim are both cut off.
    const successor = await findRefreshToken(
      stack.context.db,
      stack.scope,
      await hashToken(second.refresh_token as string),
    );
    expect(successor?.revokedAt).not.toBeNull();
    expect((await refresh(second.refresh_token as string)).status).toBe(400);

    const page = await queryAuditEvents(stack.context.db, {
      tenantId: stack.tenant.id,
      actions: ["token.refresh-reuse-detected"],
    });
    expect(page.events).toHaveLength(1);
    // One, not two: the presented token was already revoked when it was rotated, so
    // the live member the reuse response had to revoke is its successor. The key is
    // named without the word "token" on purpose — the audit redactor treats any key
    // containing it as a credential, and a redacted count is a useless one.
    expect(page.events[0]?.detail).toMatchObject({ revokedRefreshCount: 1 });
  });

  it("says the same thing about a reused token as about an unknown one", async () => {
    const first = await firstTokens();
    const rotated = first.refresh_token as string;
    await refresh(rotated);

    const reused = (await (await refresh(rotated)).json()) as TokenResponseBody;
    const unknown = (await (
      await refresh("not-a-refresh-token")
    ).json()) as TokenResponseBody;

    // Distinguishing them would tell an attacker that the legitimate client is active.
    expect(reused.error_description).toBe(unknown.error_description);
  });

  it("refuses a refresh token presented by a different client", async () => {
    const first = await firstTokens();
    const response = await postForm(stack, "/token", {
      grant_type: "refresh_token",
      refresh_token: first.refresh_token as string,
      client_id: stack.publicClient.clientId,
    });
    expect(response.status).toBe(400);

    // Not spent: the rightful owner has done nothing wrong.
    expect((await refresh(first.refresh_token as string)).status).toBe(200);
  });

  it("requires the refresh_token parameter", async () => {
    const response = await postForm(
      stack,
      "/token",
      { grant_type: "refresh_token" },
      { authorization: basicAuth(stack.symmetricClient.clientId) },
    );
    expect(((await response.json()) as TokenResponseBody).error).toBe(
      "invalid_request",
    );
  });

  it("carries the launch context forward rather than re-resolving it", async () => {
    const { code, verifier } = await authorizeToCode(stack, {
      clientId: stack.symmetricClient.clientId,
      scope: "openid offline_access launch/patient patient/Observation.rs",
      patient: "pat-2",
    });
    const first = (await (
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
    ).json()) as TokenResponseBody & { patient?: string };
    expect(first.patient).toBe("pat-2");

    const second = (await (
      await refresh(first.refresh_token as string)
    ).json()) as TokenResponseBody & { patient?: string };
    // Nobody is present at a refresh, so the patient must not change.
    expect(second.patient).toBe("pat-2");
  });
});

describeWithDatabase("introspection, revocation and UserInfo", () => {
  let stack: TestStack;

  beforeAll(async () => {
    stack = await createTestStack();
  }, 60_000);

  afterAll(async () => {
    await stack.close();
  });

  /** Runs a full authorization for the confidential client. */
  async function issue(
    scope = "openid fhirUser offline_access user/Observation.rs",
  ): Promise<TokenResponseBody> {
    const { code, verifier } = await authorizeToCode(stack, {
      clientId: stack.symmetricClient.clientId,
      scope,
    });
    return (await (
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
  }

  /** Introspects a token as the confidential client. */
  async function introspect(token: string): Promise<Record<string, unknown>> {
    const response = await postForm(
      stack,
      "/introspect",
      { token },
      { authorization: basicAuth(stack.symmetricClient.clientId) },
    );
    expect(response.status).toBe(200);
    return (await response.json()) as Record<string, unknown>;
  }

  it("reports an active token with its scope and launch context", async () => {
    const tokens = await issue(
      "openid fhirUser launch/patient patient/Observation.rs",
    );
    const body = await introspect(tokens.access_token);

    expect(body).toMatchObject({
      active: true,
      client_id: stack.symmetricClient.clientId,
      sub: stack.user.id,
      iss: stack.issuer,
      aud: stack.endpoint.fhirBaseUrl,
      token_type: "Bearer",
    });
    expect(body["patient"]).toBe("pat-1");
    // The ID token's claims ride along, which is what SMART's introspection
    // additions are for.
    expect(body["fhirUser"]).toBe("Practitioner/prac-1");
  });

  it("says nothing at all about a token it has never issued", async () => {
    await expect(introspect("not-a-token")).resolves.toEqual({ active: false });
  });

  it("reveals nothing about a revoked token beyond that it is inactive", async () => {
    const tokens = await issue();
    await postForm(
      stack,
      "/revoke",
      { token: tokens.access_token },
      { authorization: basicAuth(stack.symmetricClient.clientId) },
    );
    await expect(introspect(tokens.access_token)).resolves.toEqual({
      active: false,
    });
  });

  it("requires authentication", async () => {
    const tokens = await issue();
    const response = await postForm(stack, "/introspect", {
      token: tokens.access_token,
    });
    expect(response.status).toBe(400);
  });

  it("revokes a refresh token's whole family", async () => {
    const first = await issue();
    // Rotate once, so the family has two members and revoking only the presented row
    // would be visibly insufficient.
    const second = (await (
      await postForm(
        stack,
        "/token",
        {
          grant_type: "refresh_token",
          refresh_token: first.refresh_token as string,
        },
        { authorization: basicAuth(stack.symmetricClient.clientId) },
      )
    ).json()) as TokenResponseBody;

    const response = await postForm(
      stack,
      "/revoke",
      {
        token: second.refresh_token as string,
        token_type_hint: "refresh_token",
      },
      { authorization: basicAuth(stack.symmetricClient.clientId) },
    );
    expect(response.status).toBe(200);

    const leaf = await findRefreshToken(
      stack.context.db,
      stack.scope,
      await hashToken(second.refresh_token as string),
    );
    const family = (
      await listRefreshTokensForSubject(
        stack.context.db,
        stack.scope,
        stack.user.id,
      )
    ).filter((row) => row.familyId === leaf?.familyId);

    expect(family).toHaveLength(2);
    expect(family.every((row) => row.revokedAt !== null)).toBe(true);
  });

  it("finds a refresh token even when the hint says otherwise", async () => {
    const tokens = await issue();
    await postForm(
      stack,
      "/revoke",
      {
        token: tokens.refresh_token as string,
        token_type_hint: "access_token",
      },
      { authorization: basicAuth(stack.symmetricClient.clientId) },
    );

    const row = await findRefreshToken(
      stack.context.db,
      stack.scope,
      await hashToken(tokens.refresh_token as string),
    );
    expect(row?.revokedAt).not.toBeNull();
  });

  it("answers 200 for a token it does not recognise", async () => {
    const response = await postForm(
      stack,
      "/revoke",
      { token: "nothing-like-a-token" },
      { authorization: basicAuth(stack.symmetricClient.clientId) },
    );
    expect(response.status).toBe(200);
  });

  it("refuses to revoke another client's token", async () => {
    const tokens = await issue();
    // Presented by the public client, which did not obtain it.
    await postForm(stack, "/revoke", {
      token: tokens.refresh_token as string,
      client_id: stack.publicClient.clientId,
    });

    const row = await findRefreshToken(
      stack.context.db,
      stack.scope,
      await hashToken(tokens.refresh_token as string),
    );
    expect(row?.revokedAt).toBeNull();
  });

  it("returns the identity claims a token released", async () => {
    const tokens = await issue();
    const response = await stack.app.request(`${issuerPath(stack)}/userinfo`, {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body["sub"]).toBe(stack.user.id);
    expect(body["fhirUser"]).toBe("Practitioner/prac-1");
  });

  it("challenges a request with no token", async () => {
    const response = await stack.app.request(`${issuerPath(stack)}/userinfo`);
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toContain("Bearer");
  });

  it("reports insufficient_scope for a token without openid", async () => {
    const tokens = await issue("user/Observation.rs");
    const response = await stack.app.request(`${issuerPath(stack)}/userinfo`, {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });

    expect(response.status).toBe(403);
    expect(response.headers.get("www-authenticate")).toContain(
      "insufficient_scope",
    );
  });

  it("refuses a revoked token", async () => {
    const tokens = await issue();
    const jti = decodePayload(tokens.access_token)["jti"] as string;
    await postForm(
      stack,
      "/revoke",
      { token: tokens.access_token },
      { authorization: basicAuth(stack.symmetricClient.clientId) },
    );

    const response = await stack.app.request(`${issuerPath(stack)}/userinfo`, {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    expect(response.status).toBe(401);
    expect(
      (await introspectAccessToken(stack.context.db, stack.scope, jti))
        ?.revokedAt,
    ).not.toBeNull();
  });
});

describeWithDatabase("an endpoint with no signing key", () => {
  let stack: TestStack;

  beforeAll(async () => {
    stack = await createTestStack({ withoutSigningKey: true });
  }, 60_000);

  afterAll(async () => {
    await stack.close();
  });

  it("reports its own misconfiguration rather than blaming the client", async () => {
    const { code, verifier } = await authorizeToCode(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid",
    });
    const response = await postForm(stack, "/token", {
      grant_type: "authorization_code",
      code,
      redirect_uri: "https://app.test/cb",
      code_verifier: verifier,
      client_id: stack.publicClient.clientId,
    });

    // A 400 would send an app developer looking for a bug they do not have.
    expect(response.status).toBe(500);
    expect(
      ((await response.json()) as TokenResponseBody).error_description,
    ).toContain("no active signing key");
  });

  it("publishes an empty JWKS rather than failing", async () => {
    const response = await stack.app.request(`${issuerPath(stack)}/jwks`);
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ keys: [] });
  });
});
