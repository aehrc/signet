/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The token endpoint against a real database, one suite per grant.
 *
 * These are the assertions that matter most in the whole build, because they are the
 * only place the pieces meet: an authorization code that is refused by a conditional
 * `UPDATE` rather than by an `if`, a PKCE verifier checked against a challenge that
 * travelled through a database row, a policy resolved through a scope that proves
 * which tenant asked, and a token signed by a key that was decrypted from its
 * envelope.
 *
 * Author: John Grimes
 */

import { PATHLING_PRESET } from "@signet/core";
import {
  findAccessToken,
  introspectAccessToken,
  listRefreshTokensForSubject,
  queryAuditEvents,
  withTenantScope,
} from "@signet/db";
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { createLocalJWKSet, jwtVerify } from "jose";

import {
  authorizeToCode,
  backendToken,
  basicAuth,
  clientAssertion,
  decodePayload,
  issuerPath,
  postForm,
} from "../test/flows.js";
import {
  createTestStack,
  TEST_CLIENT_SECRET,
  testDatabaseUrl,
} from "../test/harness.js";

import type { TestStack } from "../test/harness.js";

const describeWithDatabase =
  testDatabaseUrl === undefined ? describe.skip : describe;

/** A token response body, as far as these suites read it. */
interface TokenResponseBody {
  readonly access_token: string;
  readonly token_type: string;
  readonly expires_in: number;
  readonly scope: string;
  readonly id_token?: string;
  readonly refresh_token?: string;
  readonly patient?: string;
  readonly need_patient_banner?: boolean;
  readonly error?: string;
  readonly error_description?: string;
}

/** Verifies a token against the endpoint's published JWKS. */
async function verifyAgainstJwks(
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

describeWithDatabase("the authorization_code grant", () => {
  let stack: TestStack;

  beforeAll(async () => {
    stack = await createTestStack();
  });

  afterAll(async () => {
    await stack.close();
  });

  it("issues a token the published JWKS verifies", async () => {
    const { code, verifier } = await authorizeToCode(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid fhirUser launch/patient patient/Observation.rs",
      patient: "pat-1",
    });

    const response = await postForm(stack, "/token", {
      grant_type: "authorization_code",
      code,
      redirect_uri: "https://app.test/cb",
      code_verifier: verifier,
      client_id: stack.publicClient.clientId,
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");

    const body = (await response.json()) as TokenResponseBody;
    expect(body.token_type).toBe("Bearer");
    expect(body.scope).toContain("patient/Observation.rs");
    // The SMART baseline preset passes the patient through as a response parameter.
    expect(body.patient).toBe("pat-1");
    expect(body.need_patient_banner).toBe(true);

    const claims = await verifyAgainstJwks(
      stack,
      body.access_token,
      stack.endpoint.fhirBaseUrl,
    );
    expect(claims["sub"]).toBe(stack.user.id);
    expect(claims["client_id"]).toBe(stack.publicClient.clientId);
    expect(claims["fhirUser"]).toBe("Practitioner/prac-1");
    expect(claims["scope"]).toBe(body.scope);

    // The token's metadata is recorded, or introspection and revocation could not work.
    const recorded = await withTenantScope(
      stack.context.db,
      stack.scope,
      (bound) => findAccessToken(bound, claims["jti"] as string),
    );
    expect(recorded).toMatchObject({
      subject: stack.user.id,
      audience: stack.endpoint.fhirBaseUrl,
      issuer: stack.issuer,
    });
  });

  it("issues an ID token addressed to the client, not to the FHIR server", async () => {
    const { code, verifier } = await authorizeToCode(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid fhirUser",
      nonce: "n-abc",
    });

    const body = (await (
      await postForm(stack, "/token", {
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://app.test/cb",
        code_verifier: verifier,
        client_id: stack.publicClient.clientId,
      })
    ).json()) as TokenResponseBody;

    expect(body.id_token).toBeDefined();
    const claims = await verifyAgainstJwks(
      stack,
      body.id_token as string,
      stack.publicClient.clientId,
    );
    expect(claims["fhirUser"]).toBe("Practitioner/prac-1");
    expect(claims["nonce"]).toBe("n-abc");
    expect(claims["aud"]).toBe(stack.publicClient.clientId);
  });

  it("issues no refresh token to a public client, because the policy grants none", async () => {
    const { code, verifier } = await authorizeToCode(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid offline_access",
    });

    const body = (await (
      await postForm(stack, "/token", {
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://app.test/cb",
        code_verifier: verifier,
        client_id: stack.publicClient.clientId,
      })
    ).json()) as TokenResponseBody;

    // The SMART baseline preset restricts `offline_access` to confidential clients.
    expect(body.refresh_token).toBeUndefined();
    expect(body.scope).not.toContain("offline_access");
  });

  it("issues a refresh token to a confidential client", async () => {
    const { code, verifier } = await authorizeToCode(stack, {
      clientId: stack.symmetricClient.clientId,
      scope: "openid offline_access user/Observation.rs",
    });

    const body = (await (
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

    expect(body.refresh_token).toBeDefined();
    expect(body.scope).toContain("offline_access");
  });

  it("takes the granted scopes from the session, not from the token request", async () => {
    const { code, verifier } = await authorizeToCode(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid",
    });

    const body = (await (
      await postForm(stack, "/token", {
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://app.test/cb",
        code_verifier: verifier,
        client_id: stack.publicClient.clientId,
        // Ignored entirely: there is nowhere in the grant that reads it.
        scope: "user/Observation.cruds",
      })
    ).json()) as TokenResponseBody;

    expect(body.scope).toBe("openid");
  });

  it("refuses a mismatched PKCE verifier", async () => {
    const { code } = await authorizeToCode(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid",
    });

    const response = await postForm(stack, "/token", {
      grant_type: "authorization_code",
      code,
      redirect_uri: "https://app.test/cb",
      code_verifier: "a".repeat(43),
      client_id: stack.publicClient.clientId,
    });

    expect(response.status).toBe(400);
    const body = (await response.json()) as TokenResponseBody;
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toContain("PKCE");
  });

  it("requires a code verifier at all", async () => {
    const { code } = await authorizeToCode(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid",
    });

    const body = (await (
      await postForm(stack, "/token", {
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://app.test/cb",
        client_id: stack.publicClient.clientId,
      })
    ).json()) as TokenResponseBody;

    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("PKCE is mandatory");
  });

  it("refuses a redirect URI that differs from the one the code was issued for", async () => {
    const { code, verifier } = await authorizeToCode(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid",
    });

    const body = (await (
      await postForm(stack, "/token", {
        grant_type: "authorization_code",
        code,
        // Registered, so it passes `/authorize`'s check - but not the one this code
        // was bound to.
        redirect_uri: "https://app.test/cb?x=1",
        code_verifier: verifier,
        client_id: stack.publicClient.clientId,
      })
    ).json()) as TokenResponseBody;

    expect(body.error).toBe("invalid_grant");
  });

  it("refuses a code presented by a different client", async () => {
    const { code, verifier } = await authorizeToCode(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid",
    });

    const body = (await (
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

    expect(body.error).toBe("invalid_grant");
  });

  it("refuses a replayed code and revokes what the first redemption issued", async () => {
    const { code, verifier } = await authorizeToCode(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid patient/Observation.rs",
      patient: "pat-1",
    });
    const fields = {
      grant_type: "authorization_code",
      code,
      redirect_uri: "https://app.test/cb",
      code_verifier: verifier,
      client_id: stack.publicClient.clientId,
    };

    const first = (await (
      await postForm(stack, "/token", fields)
    ).json()) as TokenResponseBody;
    const jti = decodePayload(first.access_token)["jti"] as string;

    const second = await postForm(stack, "/token", fields);
    expect(second.status).toBe(400);
    expect(((await second.json()) as TokenResponseBody).error).toBe(
      "invalid_grant",
    );

    // RFC 6749 §10.5: a replayed code means the code leaked, so the token it produced
    // must not stay live.
    const record = await withTenantScope(
      stack.context.db,
      stack.scope,
      (bound) => introspectAccessToken(bound, jti),
    );
    expect(record?.revokedAt).not.toBeNull();
  });

  it("refuses an unknown code", async () => {
    const body = (await (
      await postForm(stack, "/token", {
        grant_type: "authorization_code",
        code: "not-a-code",
        redirect_uri: "https://app.test/cb",
        code_verifier: "a".repeat(43),
        client_id: stack.publicClient.clientId,
      })
    ).json()) as TokenResponseBody;
    expect(body.error).toBe("invalid_grant");
  });

  it("records the policy version that authorised the token", async () => {
    const { code, verifier } = await authorizeToCode(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid",
    });
    await postForm(stack, "/token", {
      grant_type: "authorization_code",
      code,
      redirect_uri: "https://app.test/cb",
      code_verifier: verifier,
      client_id: stack.publicClient.clientId,
    });

    const page = await withTenantScope(
      stack.context.db,
      stack.tenantScope,
      (bound) => queryAuditEvents(bound, { actions: ["token.issued"] }),
    );
    expect(page.events[0]?.detail).toMatchObject({
      grantType: "authorization_code",
      policySource: "endpoint",
      policyVersion: 1,
      clientAuthMethod: "none",
    });
  });
});

describeWithDatabase("client authentication at the token endpoint", () => {
  let stack: TestStack;

  beforeAll(async () => {
    stack = await createTestStack();
  });

  afterAll(async () => {
    await stack.close();
  });

  /** Redeems a code for the symmetric client with the given credential fields. */
  async function redeemAsSymmetric(
    extra: Readonly<Record<string, string>>,
    headers: Readonly<Record<string, string>> = {},
  ): Promise<Response> {
    const { code, verifier } = await authorizeToCode(stack, {
      clientId: stack.symmetricClient.clientId,
      scope: "openid",
    });
    return await postForm(
      stack,
      "/token",
      {
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://app.test/cb",
        code_verifier: verifier,
        ...extra,
      },
      headers,
    );
  }

  it("accepts client_secret_basic", async () => {
    const response = await redeemAsSymmetric(
      {},
      { authorization: basicAuth(stack.symmetricClient.clientId) },
    );
    expect(response.status).toBe(200);
  });

  it("accepts client_secret_post", async () => {
    const response = await redeemAsSymmetric({
      client_id: stack.symmetricClient.clientId,
      client_secret: TEST_CLIENT_SECRET,
    });
    expect(response.status).toBe(200);
  });

  it("refuses a wrong secret with 401 and a challenge", async () => {
    const response = await redeemAsSymmetric(
      {},
      {
        authorization: basicAuth(
          stack.symmetricClient.clientId,
          "wrong-secret",
        ),
      },
    );
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toContain("Basic");
  });

  it("refuses a confidential client presenting no credential", async () => {
    const response = await redeemAsSymmetric({
      client_id: stack.symmetricClient.clientId,
    });
    expect(response.status).toBe(401);
    expect(
      ((await response.json()) as TokenResponseBody).error_description,
    ).toContain("must authenticate with a different method");
  });

  it("refuses a public client presenting a secret", async () => {
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
      client_secret: "invented",
    });
    expect(response.status).toBe(401);
  });

  it("refuses two credentials at once", async () => {
    const response = await redeemAsSymmetric(
      {
        client_id: stack.symmetricClient.clientId,
        client_secret: TEST_CLIENT_SECRET,
      },
      { authorization: basicAuth(stack.symmetricClient.clientId) },
    );
    expect(response.status).toBe(400);
  });

  it("refuses an unknown client with the same message as a wrong secret", async () => {
    const unknown = await postForm(stack, "/token", {
      grant_type: "authorization_code",
      code: "x",
      redirect_uri: "https://app.test/cb",
      code_verifier: "a".repeat(43),
      client_id: "no-such-client",
      client_secret: "whatever",
    });
    expect(unknown.status).toBe(401);
    expect(
      ((await unknown.json()) as TokenResponseBody).error_description,
    ).toBe("Client authentication failed");
  });

  it("accepts private_key_jwt", async () => {
    const { code, verifier } = await authorizeToCode(stack, {
      clientId: stack.asymmetricClient.client.clientId,
      scope: "openid",
    });
    const response = await postForm(stack, "/token", {
      grant_type: "authorization_code",
      code,
      redirect_uri: "https://app.test/cb",
      code_verifier: verifier,
      client_assertion_type:
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: await clientAssertion(stack, stack.asymmetricClient),
    });
    expect(response.status).toBe(200);
  });
});

describeWithDatabase("the client_credentials grant", () => {
  let stack: TestStack;

  beforeAll(async () => {
    stack = await createTestStack({ policy: PATHLING_PRESET });
  });

  afterAll(async () => {
    await stack.close();
  });

  it("issues a token carrying Pathling's authorities", async () => {
    const response = await backendToken(stack, "system/Observation.rs");
    expect(response.status).toBe(200);

    const body = (await response.json()) as TokenResponseBody;
    const claims = await verifyAgainstJwks(
      stack,
      body.access_token,
      stack.endpoint.fhirBaseUrl,
    );

    // The whole point of the policy engine: SMART scopes in, vendor authorities out.
    // The operations after `search` all follow from the `r` permission, and each is
    // still bounded by the typed read authority in front of them - see the preset's
    // commentary.
    expect(claims["authorities"]).toEqual([
      "pathling:read:Observation",
      "pathling:search",
      "pathling:read-resource",
      "pathling:export",
      "pathling:sql-run",
      "pathling:sql-export",
      "pathling:jobs",
    ]);
    // The backend service is its own subject.
    expect(claims["sub"]).toBe(stack.backendClient.client.clientId);
  });

  it("never issues a refresh token to a backend service", async () => {
    const body = (await (
      await backendToken(stack, "system/Observation.rs")
    ).json()) as TokenResponseBody;
    expect(body.refresh_token).toBeUndefined();
    expect(
      await withTenantScope(stack.context.db, stack.scope, (bound) =>
        listRefreshTokensForSubject(bound, stack.backendClient.client.clientId),
      ),
    ).toHaveLength(0);
  });

  it("refuses a replayed client assertion", async () => {
    const jti = crypto.randomUUID();
    const first = await backendToken(stack, "system/Observation.rs", { jti });
    expect(first.status).toBe(200);

    const replay = await backendToken(stack, "system/Observation.rs", { jti });
    expect(replay.status).toBe(401);
    expect(
      ((await replay.json()) as TokenResponseBody).error_description,
    ).toContain("already been presented");

    const page = await withTenantScope(
      stack.context.db,
      stack.tenantScope,
      (bound) =>
        queryAuditEvents(bound, { actions: ["token.jti-replay-detected"] }),
    );
    expect(page.events).toHaveLength(1);
  });

  it("refuses an assertion addressed to another server", async () => {
    const response = await backendToken(stack, "system/Observation.rs", {
      audience: "https://other.example/token",
    });
    expect(response.status).toBe(401);
    expect(
      ((await response.json()) as TokenResponseBody).error_description,
    ).toContain("aud");
  });

  it("refuses an assertion whose sub is another client", async () => {
    const response = await backendToken(stack, "system/Observation.rs", {
      subject: stack.asymmetricClient.client.clientId,
      issuer: stack.asymmetricClient.client.clientId,
    });
    expect(response.status).toBe(401);
  });

  it("refuses an assertion valid for too long", async () => {
    const response = await backendToken(stack, "system/Observation.rs", {
      expiresInSeconds: 86_400,
    });
    expect(response.status).toBe(401);
    expect(
      ((await response.json()) as TokenResponseBody).error_description,
    ).toContain("more than");
  });

  it("refuses a scope outside the client's allowlist", async () => {
    const response = await backendToken(stack, "https://example.org/custom");
    expect(response.status).toBe(400);
    expect(
      ((await response.json()) as TokenResponseBody).error_description,
    ).toContain("allowlist");
  });

  it("requires a scope", async () => {
    const response = await postForm(stack, "/token", {
      grant_type: "client_credentials",
      client_assertion_type:
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: await clientAssertion(stack, stack.backendClient),
    });
    expect(((await response.json()) as TokenResponseBody).error).toBe(
      "invalid_scope",
    );
  });

  it("refuses a client not registered for the grant", async () => {
    const response = await postForm(stack, "/token", {
      grant_type: "client_credentials",
      scope: "system/Observation.rs",
      client_assertion_type:
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: await clientAssertion(stack, stack.asymmetricClient),
    });
    expect(((await response.json()) as TokenResponseBody).error).toBe(
      "unauthorized_client",
    );
  });

  it("refuses an unsupported grant type", async () => {
    const response = await postForm(stack, "/token", {
      grant_type: "password",
      client_id: stack.publicClient.clientId,
    });
    expect(((await response.json()) as TokenResponseBody).error).toBe(
      "unsupported_grant_type",
    );
  });
});
