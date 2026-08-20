/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Refresh, introspection, revocation and UserInfo, against a real database.
 *
 * The refresh suite is the one worth reading twice. Rotation is only useful if reuse
 * of a rotated token is detected, and detection is only useful if it revokes the
 * whole family - so both are asserted, along with the property that a client bug
 * (asking for a scope it does not hold) does *not* cost the user their session.
 *
 * Author: John Grimes
 */

import {
  createVouchedClient,
  decryptSecret,
  deleteEndpointTrustAnchor,
  findRefreshToken,
  hashPassword,
  hashToken,
  introspectAccessToken,
  listRefreshTokensForSubject,
  queryAuditEvents,
  upsertEndpointTrustAnchor,
  withTenantScope,
} from "@signet/db";
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { importJWK, SignJWT } from "jose";

import { generateEndpointKey } from "../keys/material.js";
import {
  authorizeToCode,
  basicAuth,
  decodePayload,
  issuerPath,
  postForm,
} from "../test/flows.js";
import {
  createTestStack,
  TEST_CLIENT_SECRET,
  TEST_MASTER_KEY,
  testDatabaseUrl,
} from "../test/harness.js";

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
  });

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

    const row = await withTenantScope(
      stack.context.db,
      stack.scope,
      async (bound) => findRefreshToken(bound, await hashToken(presented)),
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
    const successor = await withTenantScope(
      stack.context.db,
      stack.scope,
      async (bound) =>
        findRefreshToken(
          bound,
          await hashToken(second.refresh_token as string),
        ),
    );
    expect(successor?.revokedAt).not.toBeNull();
    expect((await refresh(second.refresh_token as string)).status).toBe(400);

    const page = await withTenantScope(
      stack.context.db,
      stack.tenantScope,
      (bound) =>
        queryAuditEvents(bound, { actions: ["token.refresh-reuse-detected"] }),
    );
    expect(page.events).toHaveLength(1);
    // One, not two: the presented token was already revoked when it was rotated, so
    // the live member the reuse response had to revoke is its successor. The key is
    // named without the word "token" on purpose - the audit redactor treats any key
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
  });

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

    const leaf = await withTenantScope(
      stack.context.db,
      stack.scope,
      async (bound) =>
        findRefreshToken(
          bound,
          await hashToken(second.refresh_token as string),
        ),
    );
    const family = (
      await withTenantScope(stack.context.db, stack.scope, (bound) =>
        listRefreshTokensForSubject(bound, stack.user.id),
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

    const row = await withTenantScope(
      stack.context.db,
      stack.scope,
      async (bound) =>
        findRefreshToken(
          bound,
          await hashToken(tokens.refresh_token as string),
        ),
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

    const row = await withTenantScope(
      stack.context.db,
      stack.scope,
      async (bound) =>
        findRefreshToken(
          bound,
          await hashToken(tokens.refresh_token as string),
        ),
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
      (
        await withTenantScope(stack.context.db, stack.scope, (bound) =>
          introspectAccessToken(bound, jti),
        )
      )?.revokedAt,
    ).not.toBeNull();
  });
});

describeWithDatabase("a vouched client's expiry", () => {
  let stack: TestStack;

  /**
   * The instant the harness clock starts at, so expiry is the test's to choose.
   *
   * Read from the stack rather than fixed, and only ever moved *forwards*. The
   * repositories compare expiry against the database's own clock, so a process
   * clock wound back would write rows the database considers already expired -
   * which fails as an unrelated "session does not exist" rather than as anything
   * about vouching.
   */
  let START: Date;

  beforeAll(async () => {
    stack = await createTestStack();
    START = stack.context.clock();
  });

  afterAll(async () => {
    await stack.close();
  });

  /**
   * Registers a client an anchor vouched for, directly.
   *
   * Through the repository rather than through `/register`, so that what is being
   * asserted is the enforcement at issuance and not the registration route: the
   * expiry has to bite for a vouched client however it came to exist.
   */
  async function vouchedClient(
    expiresAt: Date,
    overrides: Partial<Parameters<typeof createVouchedClient>[1]> = {},
  ) {
    const suffix = crypto.randomUUID().slice(0, 8);
    return await withTenantScope(stack.context.db, stack.scope, (bound) =>
      createVouchedClient(
        bound,
        {
          clientId: `vouched-${suffix}`,
          name: "Vouched app",
          clientType: "public",
          redirectUris: ["https://app.test/cb"],
          grantTypes: ["authorization_code", "refresh_token"],
          allowedScopes: ["openid", "offline_access", "user/Observation.rs"],
          status: "active",
          ...overrides,
        },
        {
          vouchedByIssuer: "https://anchor.test",
          vouchedStatementId: `statement-${suffix}`,
          vouchingExpiresAt: expiresAt,
        },
      ),
    );
  }

  it("issues tokens right up to the expiry and refuses every grant after it", async () => {
    // SC-005 measured directly: a request that succeeded before the boundary is
    // repeated after it, and the only thing that changed is the clock.
    //
    // Confidential, because the baseline preset grants `offline_access` only to a
    // client that can authenticate - and the refresh grant is the half of this
    // that a per-grant check would miss.
    const client = await vouchedClient(new Date(START.getTime() + 3_600_000), {
      clientType: "confidential-symmetric",
      secretHash: await hashPassword(TEST_CLIENT_SECRET),
    });

    const first = await authorizeToCode(stack, {
      clientId: client.clientId,
      scope: "openid offline_access user/Observation.rs",
    });
    const issued = (await (
      await postForm(
        stack,
        "/token",
        {
          grant_type: "authorization_code",
          code: first.code,
          redirect_uri: "https://app.test/cb",
          code_verifier: first.verifier,
          client_id: client.clientId,
        },
        { authorization: basicAuth(client.clientId) },
      )
    ).json()) as TokenResponseBody;
    expect(issued.access_token).toBeDefined();
    expect(issued.refresh_token).toBeDefined();

    // A second authorization, redeemed after the vouching lapses. The code is
    // minted while the client is live so that the refusal is the vouching rather
    // than anything about the code.
    const second = await authorizeToCode(stack, {
      clientId: client.clientId,
      scope: "openid user/Observation.rs",
    });
    stack.setNow(new Date(START.getTime() + 7_200_000));

    const afterwards = await postForm(
      stack,
      "/token",
      {
        grant_type: "authorization_code",
        code: second.code,
        redirect_uri: "https://app.test/cb",
        code_verifier: second.verifier,
        client_id: client.clientId,
      },
      { authorization: basicAuth(client.clientId) },
    );
    expect(afterwards.status).toBe(401);
    expect(
      ((await afterwards.json()) as TokenResponseBody).error_description,
    ).toContain("vouching");

    // The refresh grant too: the token was issued while the client was live and
    // would otherwise outlive the vouching by its own lifetime.
    const refreshed = await postForm(
      stack,
      "/token",
      {
        grant_type: "refresh_token",
        refresh_token: issued.refresh_token ?? "",
        client_id: client.clientId,
      },
      { authorization: basicAuth(client.clientId) },
    );
    expect(refreshed.status).toBe(401);
    expect(((await refreshed.json()) as TokenResponseBody).error).toBe(
      "invalid_client",
    );

    stack.setNow(START);
  });

  it("refuses a backend service's grant once its vouching has lapsed", async () => {
    // Every grant type, not only the interactive ones. `client_credentials`
    // reaches issuance by a different path and must meet the same refusal.
    const key = await generateEndpointKey("RS384", TEST_MASTER_KEY);
    const client = await vouchedClient(new Date(START.getTime() + 3_600_000), {
      clientType: "confidential-asymmetric",
      jwks: { keys: [key.publicJwk] },
      grantTypes: ["client_credentials"],
      redirectUris: [],
      allowedScopes: ["system/Observation.rs"],
    });
    stack.setNow(new Date(START.getTime() + 7_200_000));

    const assertion = await new SignJWT({})
      .setProtectedHeader({ alg: "RS384" })
      .setIssuer(client.clientId)
      .setSubject(client.clientId)
      .setAudience(`${stack.issuer}/token`)
      .setJti(crypto.randomUUID())
      .setIssuedAt(Math.floor(stack.context.clock().getTime() / 1000))
      .setExpirationTime(
        Math.floor(stack.context.clock().getTime() / 1000) + 60,
      )
      .sign(
        await importJWK(
          JSON.parse(
            await decryptSecret(key.privateJwkEncrypted, TEST_MASTER_KEY),
          ) as Record<string, unknown>,
          "RS384",
        ),
      );

    const response = await postForm(stack, "/token", {
      grant_type: "client_credentials",
      scope: "system/Observation.rs",
      client_assertion_type:
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: assertion,
    });

    expect(response.status).toBe(401);
    expect(((await response.json()) as TokenResponseBody).error).toBe(
      "invalid_client",
    );

    stack.setNow(START);
  });

  it("leaves a client an administrator created entirely alone", async () => {
    // The enforcement must key on the expiry, not on being a client: a portal or
    // console client carries no expiry and must be unaffected by any of this.
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
    expect(response.status).toBe(200);
  });

  it("keeps working after the anchor rule that created it is removed", async () => {
    // Removing the rule refuses new registrations. It is not a revocation of the
    // clients already registered, which carry their own expiry and nothing else.
    const client = await vouchedClient(new Date(START.getTime() + 3_600_000));
    await withTenantScope(stack.context.db, stack.scope, (bound) =>
      upsertEndpointTrustAnchor(bound, {
        issuer: "https://anchor.test",
        jwksUri: "https://anchor.test/jwks",
        maxVouchingDays: 30,
      }),
    );
    await withTenantScope(stack.context.db, stack.scope, (bound) =>
      deleteEndpointTrustAnchor(bound),
    );

    const { code, verifier } = await authorizeToCode(stack, {
      clientId: client.clientId,
      scope: "openid user/Observation.rs",
    });
    const response = await postForm(stack, "/token", {
      grant_type: "authorization_code",
      code,
      redirect_uri: "https://app.test/cb",
      code_verifier: verifier,
      client_id: client.clientId,
    });

    expect(response.status).toBe(200);
  });
});

describeWithDatabase("an endpoint with no signing key", () => {
  let stack: TestStack;

  beforeAll(async () => {
    stack = await createTestStack({ withoutSigningKey: true });
  });

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
