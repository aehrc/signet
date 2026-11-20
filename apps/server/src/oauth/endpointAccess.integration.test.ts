/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * One tenant account, several endpoints: what access to an endpoint means at sign-in,
 * in the picker and at refresh.
 *
 * An account belongs to the tenant and has one password, but signs in only where it
 * has been given access, and each endpoint it can use names it by that endpoint's own
 * `fhirUser`. Withdrawing access at one endpoint ends what the account holds there and
 * nothing it holds anywhere else.
 *
 * Author: John Grimes
 */

import { afterAll, beforeAll, describe, expect, it } from "bun:test";

import {
  adminJson,
  adminRequest,
  endpointPath,
  tenantPath,
} from "../test/adminApi.js";
import {
  authorizeToCode,
  basicAuth,
  decodePayload,
  interactionState,
  login,
  pkcePair,
  postForm,
  startAuthorization,
} from "../test/flows.js";
import {
  createTestStack,
  TEST_PASSWORD,
  testDatabaseUrl,
} from "../test/harness.js";

import type { AdminCredential } from "../test/adminApi.js";
import type { TestStack } from "../test/harness.js";

/** A token response body, as far as this suite reads it. */
interface TokenResponseBody {
  readonly access_token: string;
  readonly id_token?: string;
  readonly refresh_token?: string;
  readonly error?: string;
}

describe.skipIf(testDatabaseUrl === undefined)("access to an endpoint", () => {
  let stack: TestStack;
  let second: TestStack;
  let owner: AdminCredential;

  beforeAll(async () => {
    stack = await createTestStack();
    owner = { cookie: await stack.signIn() };
    second = await stack.addEndpoint({ slug: "second" });
  });

  afterAll(async () => {
    await stack.close();
  });

  /** Gives an account access to an endpoint, with that endpoint's fields. */
  async function grant(
    at: TestStack,
    userId: string,
    body: Record<string, unknown> = {},
  ): Promise<void> {
    await adminJson(stack, "PUT", endpointPath(at, `/users/${userId}`), {
      credential: owner,
      body,
    });
  }

  /** Withdraws an account's access to an endpoint. */
  async function revoke(at: TestStack, userId: string): Promise<void> {
    const response = await adminRequest(
      stack,
      "DELETE",
      endpointPath(at, `/users/${userId}`),
      { credential: owner },
    );
    expect(response.status).toBe(204);
  }

  /** Signs the fixture clinician in at an endpoint and redeems the code. */
  async function tokensAt(at: TestStack): Promise<TokenResponseBody> {
    const { code, verifier } = await authorizeToCode(at, {
      clientId: at.symmetricClient.clientId,
      scope: "openid fhirUser offline_access user/Observation.rs",
    });
    const response = await postForm(
      at,
      "/token",
      {
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://app.test/cb",
        code_verifier: verifier,
      },
      { authorization: basicAuth(at.symmetricClient.clientId) },
    );
    expect(response.status).toBe(200);
    return (await response.json()) as TokenResponseBody;
  }

  /** Presents a refresh token at an endpoint. */
  async function refresh(
    at: TestStack,
    refreshToken: string,
  ): Promise<Response> {
    return await postForm(
      at,
      "/token",
      { grant_type: "refresh_token", refresh_token: refreshToken },
      { authorization: basicAuth(at.symmetricClient.clientId) },
    );
  }

  /** Attempts a password sign-in at an endpoint's authorization. */
  async function signInAt(
    at: TestStack,
    username: string,
    password: string,
  ): Promise<Response> {
    const pkce = await pkcePair();
    const session = await startAuthorization(at, {
      clientId: at.publicClient.clientId,
      scope: "openid",
      challenge: pkce.challenge,
    });
    return await login(at, session, { username, password });
  }

  it("refuses an account at an endpoint it has no access to, as a wrong password is", async () => {
    // The clinician has access to the fixture endpoint alone so far.
    const noAccess = await signInAt(second, "clinician", TEST_PASSWORD);
    const wrongPassword = await signInAt(stack, "clinician", "not-it-at-all");
    expect(noAccess.status).toBe(401);
    expect(wrongPassword.status).toBe(401);
    expect(await noAccess.json()).toEqual(await wrongPassword.json());
  });

  it("does not offer a persona in the picker of an endpoint it has no access to", async () => {
    const personasAt = async (at: TestStack) => {
      const pkce = await pkcePair();
      const session = await startAuthorization(at, {
        clientId: at.publicClient.clientId,
        scope: "openid launch/patient patient/Observation.rs",
        challenge: pkce.challenge,
      });
      return (await interactionState(at, session)).personas.map(
        (persona) => persona.id,
      );
    };

    expect(await personasAt(stack)).toContain(stack.persona.id);
    expect(await personasAt(second)).not.toContain(stack.persona.id);

    // Nor can it be chosen by naming it.
    const pkce = await pkcePair();
    const session = await startAuthorization(second, {
      clientId: second.publicClient.clientId,
      scope: "openid",
      challenge: pkce.challenge,
    });
    const chosen = await login(second, session, {
      personaId: stack.persona.id,
    });
    expect(chosen.status).toBe(401);

    // Granting access is what puts it there.
    await grant(second, stack.persona.id, {
      defaultContext: { patient: "pat-2" },
    });
    expect(await personasAt(second)).toContain(stack.persona.id);
  });

  it("signs one account in at two endpoints with one password, named by each endpoint's fhirUser", async () => {
    await grant(second, stack.user.id, {
      fhirUserReference: "Practitioner/second-7",
    });

    const atFirst = await tokensAt(stack);
    const atSecond = await tokensAt(second);

    const firstClaims = decodePayload(atFirst.id_token ?? "");
    const secondClaims = decodePayload(atSecond.id_token ?? "");
    expect(firstClaims["sub"]).toBe(stack.user.id);
    expect(secondClaims["sub"]).toBe(stack.user.id);
    expect(String(firstClaims["fhirUser"])).toEndWith("Practitioner/prac-1");
    expect(String(secondClaims["fhirUser"])).toEndWith("Practitioner/second-7");

    const introspected = await postForm(
      second,
      "/introspect",
      { token: atSecond.access_token },
      { authorization: basicAuth(second.symmetricClient.clientId) },
    );
    expect(
      ((await introspected.json()) as Record<string, unknown>)["fhirUser"],
    ).toBe("Practitioner/second-7");
  });

  it("refuses a refresh at an endpoint whose access was withdrawn, and only there", async () => {
    await grant(second, stack.user.id);
    const atFirst = await tokensAt(stack);
    const atSecond = await tokensAt(second);

    await revoke(second, stack.user.id);
    try {
      const refused = await refresh(second, atSecond.refresh_token ?? "");
      expect(refused.status).toBe(400);
      expect(((await refused.json()) as TokenResponseBody).error).toBe(
        "invalid_grant",
      );

      const kept = await refresh(stack, atFirst.refresh_token ?? "");
      expect(kept.status).toBe(200);

      // An access token already issued there runs to its expiry.
      const introspected = await postForm(
        second,
        "/introspect",
        { token: atSecond.access_token },
        { authorization: basicAuth(second.symmetricClient.clientId) },
      );
      expect(
        ((await introspected.json()) as Record<string, unknown>)["active"],
      ).toBe(true);

      // Signing in there again is refused too.
      expect((await signInAt(second, "clinician", TEST_PASSWORD)).status).toBe(
        401,
      );
    } finally {
      await grant(second, stack.user.id);
    }

    // Giving access back does not revive what the withdrawal ended: the token was
    // revoked, not merely refused while access was missing, so the app must be
    // authorised again.
    const revived = await refresh(second, atSecond.refresh_token ?? "");
    expect(revived.status).toBe(400);
    expect(((await revived.json()) as TokenResponseBody).error).toBe(
      "invalid_grant",
    );
  });

  it("refuses a disabled account at every endpoint it has access to", async () => {
    await grant(second, stack.user.id);
    const userPath = tenantPath(stack, `/users/${stack.user.id}`);

    await adminJson(stack, "PATCH", userPath, {
      credential: owner,
      body: { disabled: true },
    });
    try {
      for (const at of [stack, second]) {
        expect((await signInAt(at, "clinician", TEST_PASSWORD)).status).toBe(
          401,
        );
      }
    } finally {
      await adminJson(stack, "PATCH", userPath, {
        credential: owner,
        body: { disabled: false },
      });
    }
    expect((await signInAt(second, "clinician", TEST_PASSWORD)).status).toBe(
      200,
    );
  });
});
