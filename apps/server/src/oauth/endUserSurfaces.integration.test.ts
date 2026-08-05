/**
 * The management endpoint and the developer portal, against a real database.
 *
 * The properties worth asserting are the ones that involve more than one table. That
 * withdrawing an app's access revokes the tokens it already holds - not just the consent -
 * is the difference between "disconnect" meaning what a person expects and meaning
 * nothing for the next five minutes. That withdrawing one app leaves the others alone is
 * the mistake a broader `WHERE` clause would make. And that a tracking token is required
 * to follow a request up, and only reveals a client identifier once an administrator has
 * approved it.
 *
 * Author: John Grimes
 */

import {
  clientScopeFromRow,
  listConsentsForEndUser,
  recordConsent,
  withTenantScope,
} from "@signet/db";
import { afterAll, beforeAll, describe, expect, it } from "bun:test";

import { adminRequest, endpointPath } from "../test/adminApi.js";
import { authorizeToCode, issuerPath, postForm } from "../test/flows.js";
import {
  createTestStack,
  TEST_PASSWORD,
  testDatabaseUrl,
} from "../test/harness.js";

import type { TestStack } from "../test/harness.js";

/** Signs an end user in to the management page and returns the cookie to send back. */
async function manageSignIn(
  stack: TestStack,
  credentials: Record<string, string>,
): Promise<string> {
  const response = await stack.app.request(
    `${issuerPath(stack)}/manage/session`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(credentials),
    },
  );
  const cookie = response.headers.get("set-cookie");
  if (response.status !== 200 || cookie === null) {
    throw new Error(
      `management sign-in failed: ${String(response.status)} ${await response.text()}`,
    );
  }
  return cookie.split(";", 1)[0] ?? "";
}

describe.skipIf(testDatabaseUrl === undefined)(
  "the management endpoint",
  () => {
    let stack: TestStack;

    beforeAll(async () => {
      stack = await createTestStack({ endpoint: { consentMode: "remember" } });
    });

    afterAll(async () => {
      await stack.close();
    });

    it("refuses to list anything without a session", async () => {
      const response = await stack.app.request(
        `${issuerPath(stack)}/manage/authorizations`,
      );
      expect(response.status).toBe(401);
    });

    it("scopes the session cookie to the endpoint's own path", async () => {
      const response = await stack.app.request(
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

      const cookie = response.headers.get("set-cookie") ?? "";
      // Not `Path=/`: a session on one endpoint must not be sent to another, because
      // the two hold separate accounts with separate passwords.
      expect(cookie).toContain(`Path=${issuerPath(stack)}`);
      expect(cookie).toContain("HttpOnly");
    });

    it("answers a wrong password the same way as an unknown account", async () => {
      const unknown = await stack.app.request(
        `${issuerPath(stack)}/manage/session`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ username: "nobody", password: "whatever" }),
        },
      );
      const wrong = await stack.app.request(
        `${issuerPath(stack)}/manage/session`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ username: "clinician", password: "wrong" }),
        },
      );

      expect(unknown.status).toBe(401);
      expect(await unknown.json()).toEqual(await wrong.json());
    });

    it("lists what the person has consented to", async () => {
      await withTenantScope(
        stack.context.db,
        clientScopeFromRow(stack.scope, stack.publicClient),
        (bound) =>
          recordConsent(bound, {
            endUserId: stack.user.id,
            scope: "openid patient/Observation.rs",
            expiresAt: null,
          }),
      );

      const cookie = await manageSignIn(stack, {
        username: "clinician",
        password: TEST_PASSWORD,
      });
      const response = await stack.app.request(
        `${issuerPath(stack)}/manage/authorizations`,
        { headers: { cookie } },
      );

      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        user: { username: string };
        authorizations: {
          clientId: string;
          scope: string[];
          active: boolean;
        }[];
      };
      expect(body.user.username).toBe("clinician");
      const entry = body.authorizations.find(
        (candidate) => candidate.clientId === stack.publicClient.clientId,
      );
      expect(entry?.active).toBe(true);
      expect(entry?.scope).toContain("patient/Observation.rs");
    });

    it("withdraws the consent and the tokens the app already holds", async () => {
      // A real authorization, so there is a real token to revoke.
      const { code, verifier } = await authorizeToCode(stack, {
        clientId: stack.publicClient.clientId,
        scope: "openid patient/Observation.rs",
      });
      const issued = (await (
        await postForm(stack, "/token", {
          grant_type: "authorization_code",
          code,
          redirect_uri: "https://app.test/cb",
          client_id: stack.publicClient.clientId,
          code_verifier: verifier,
        })
      ).json()) as { access_token: string };
      expect(issued.access_token).toBeDefined();

      const cookie = await manageSignIn(stack, {
        username: "clinician",
        password: TEST_PASSWORD,
      });
      const revoked = await stack.app.request(
        `${issuerPath(stack)}/manage/revoke`,
        {
          method: "POST",
          headers: { cookie, "content-type": "application/json" },
          body: JSON.stringify({ clientId: stack.publicClient.clientId }),
        },
      );

      expect(revoked.status).toBe(200);
      const counts = (await revoked.json()) as {
        consentsRevoked: number;
        accessTokensRevoked: number;
      };
      expect(counts.consentsRevoked).toBeGreaterThan(0);
      // The point of the whole endpoint: the token stops working now, not when it
      // happens to expire.
      expect(counts.accessTokensRevoked).toBeGreaterThan(0);

      const introspection = (await (
        await postForm(stack, "/introspect", {
          token: issued.access_token,
          client_id: stack.publicClient.clientId,
        })
      ).json()) as { active: boolean };
      expect(introspection.active).toBe(false);
    });

    it("leaves another app's access alone", async () => {
      const other = await createTestStack({
        endpoint: { consentMode: "remember" },
      });
      try {
        const scope = clientScopeFromRow(other.scope, other.publicClient);
        const otherScope = clientScopeFromRow(
          other.scope,
          other.symmetricClient,
        );
        await withTenantScope(other.context.db, scope, (bound) =>
          recordConsent(bound, {
            endUserId: other.user.id,
            scope: "patient/Observation.rs",
            expiresAt: null,
          }),
        );
        await withTenantScope(other.context.db, otherScope, (bound) =>
          recordConsent(bound, {
            endUserId: other.user.id,
            scope: "patient/Condition.rs",
            expiresAt: null,
          }),
        );

        const cookie = await manageSignIn(other, {
          username: "clinician",
          password: TEST_PASSWORD,
        });
        await other.app.request(`${issuerPath(other)}/manage/revoke`, {
          method: "POST",
          headers: { cookie, "content-type": "application/json" },
          body: JSON.stringify({ clientId: other.publicClient.clientId }),
        });

        const consents = await withTenantScope(
          other.context.db,
          other.scope,
          (bound) => listConsentsForEndUser(bound, other.user.id),
        );
        const survivor = consents.find(
          (entry) => entry.client.clientId === other.symmetricClient.clientId,
        );
        expect(survivor?.consent.revokedAt).toBeNull();
      } finally {
        await other.close();
      }
    });

    it("stops honouring the cookie after signing out", async () => {
      const cookie = await manageSignIn(stack, {
        username: "clinician",
        password: TEST_PASSWORD,
      });
      const signOut = await stack.app.request(
        `${issuerPath(stack)}/manage/session`,
        { method: "DELETE", headers: { cookie } },
      );
      expect(signOut.status).toBe(204);

      const after = await stack.app.request(
        `${issuerPath(stack)}/manage/authorizations`,
        { headers: { cookie } },
      );
      expect(after.status).toBe(401);
    });

    it("accepts a persona on a non-production endpoint", async () => {
      // A connectathon endpoint's accounts have no passwords, and a management page
      // nobody could open would be a management page that does not exist.
      const cookie = await manageSignIn(stack, { personaId: stack.persona.id });
      const response = await stack.app.request(
        `${issuerPath(stack)}/manage/authorizations`,
        { headers: { cookie } },
      );
      expect(response.status).toBe(200);
    });

    it("refuses a persona on a production endpoint", async () => {
      const production = await createTestStack({
        endpoint: { isProduction: true },
      });
      try {
        const response = await production.app.request(
          `${issuerPath(production)}/manage/session`,
          {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ personaId: production.persona.id }),
          },
        );
        expect(response.status).toBe(401);
      } finally {
        await production.close();
      }
    });

    it("does not honour a session from another endpoint", async () => {
      const other = await createTestStack();
      try {
        const cookie = await manageSignIn(other, {
          username: "clinician",
          password: TEST_PASSWORD,
        });
        // Same cookie name, different endpoint. The path scoping stops a browser
        // sending it; the endpoint predicate stops the server honouring it if one did.
        const response = await stack.app.request(
          `${issuerPath(stack)}/manage/authorizations`,
          { headers: { cookie } },
        );
        expect(response.status).toBe(401);
      } finally {
        await other.close();
      }
    });

    it("still finds an unrevoked token after a failed revocation attempt", async () => {
      const cookie = await manageSignIn(stack, {
        username: "clinician",
        password: TEST_PASSWORD,
      });
      const response = await stack.app.request(
        `${issuerPath(stack)}/manage/revoke`,
        {
          method: "POST",
          headers: { cookie, "content-type": "application/json" },
          body: JSON.stringify({ clientId: "no-such-client" }),
        },
      );
      expect(response.status).toBe(404);
    });
  },
);

describe.skipIf(testDatabaseUrl === undefined)("the developer portal", () => {
  let stack: TestStack;

  beforeAll(async () => {
    stack = await createTestStack({
      endpoint: { supportsDynamicRegistration: true },
    });
  });

  afterAll(async () => {
    await stack.close();
  });

  /** A well-formed submission. */
  const submission = {
    name: "Growth Chart",
    contactEmail: "dev@example.org",
    clientType: "public",
    redirectUris: ["https://growth.test/cb"],
    requestedScopes: ["openid", "patient/Observation.rs"],
    note: "Plots a child's growth against reference curves.",
  };

  /** Files a request and returns what the portal was told. */
  const submit = async (body: unknown = submission) =>
    await stack.app.request(`${issuerPath(stack)}/apps/requests`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });

  it("files a request and returns a tracking token once", async () => {
    const response = await submit();
    expect(response.status).toBe(201);

    const body = (await response.json()) as {
      request: { id: string; status: string };
      trackingToken: string;
    };
    expect(body.request.status).toBe("pending");
    expect(body.trackingToken.length).toBeGreaterThan(20);
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("refuses a malformed submission with field-level issues", async () => {
    const response = await submit({ name: "" });
    expect(response.status).toBe(400);
    const body = (await response.json()) as { issues: { path: string }[] };
    expect(body.issues.length).toBeGreaterThan(0);
  });

  it("requires the tracking token to follow a request up", async () => {
    const filed = (await (await submit()).json()) as {
      request: { id: string };
      trackingToken: string;
    };

    const without = await stack.app.request(
      `${issuerPath(stack)}/apps/requests/${filed.request.id}`,
    );
    expect(without.status).toBe(401);

    const wrong = await stack.app.request(
      `${issuerPath(stack)}/apps/requests/${filed.request.id}`,
      { headers: { authorization: "Bearer not-the-token" } },
    );
    expect(wrong.status).toBe(404);

    const right = await stack.app.request(
      `${issuerPath(stack)}/apps/requests/${filed.request.id}`,
      { headers: { authorization: `Bearer ${filed.trackingToken}` } },
    );
    expect(right.status).toBe(200);
  });

  it("answers an unknown request the same way as a wrong token", async () => {
    const unknown = await stack.app.request(
      `${issuerPath(stack)}/apps/requests/00000000-0000-0000-0000-000000000000`,
      { headers: { authorization: "Bearer anything" } },
    );
    expect(unknown.status).toBe(404);
  });

  it("reveals the client identifier once an administrator approves", async () => {
    const filed = (await (await submit()).json()) as {
      request: { id: string };
      trackingToken: string;
    };

    const before = (await (
      await stack.app.request(
        `${issuerPath(stack)}/apps/requests/${filed.request.id}`,
        { headers: { authorization: `Bearer ${filed.trackingToken}` } },
      )
    ).json()) as { clientId?: string };
    expect(before.clientId).toBeUndefined();

    const cookie = await stack.signIn();
    const approved = await adminRequest(
      stack,
      "POST",
      endpointPath(stack, `/client-requests/${filed.request.id}/approve`),
      { credential: { cookie }, body: {} },
    );
    expect(approved.status).toBe(200);

    const after = (await (
      await stack.app.request(
        `${issuerPath(stack)}/apps/requests/${filed.request.id}`,
        { headers: { authorization: `Bearer ${filed.trackingToken}` } },
      )
    ).json()) as {
      request: { status: string };
      clientId?: string;
      wellKnown?: string;
    };
    expect(after.request.status).toBe("approved");
    expect(after.clientId).toBeDefined();
    expect(after.wellKnown).toContain("/.well-known/smart-configuration");

    // The registration is readable, and carries nothing secret.
    const registration = await stack.app.request(
      `${issuerPath(stack)}/apps/registration/${String(after.clientId)}`,
    );
    expect(registration.status).toBe(200);
    const body = (await registration.json()) as Record<string, unknown>;
    expect(Object.keys(body)).not.toContain("secret");
    expect(Object.keys(body)).not.toContain("secretHash");
  });

  it("is off on an endpoint that does not accept requests", async () => {
    const closed = await createTestStack();
    try {
      const response = await closed.app.request(
        `${issuerPath(closed)}/apps/requests`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(submission),
        },
      );
      expect(response.status).toBe(404);
    } finally {
      await closed.close();
    }
  });

  it("records the submission in the audit trail", async () => {
    const filed = (await (await submit()).json()) as {
      request: { id: string };
    };

    const cookie = await stack.signIn();
    const audit = await adminRequest(
      stack,
      "GET",
      `/api/v1/tenants/${stack.tenant.slug}/audit?action=client-request.submitted`,
      { credential: { cookie } },
    );
    const body = (await audit.json()) as {
      events: { targetId: string; detail: Record<string, unknown> }[];
    };
    const event = body.events.find(
      (candidate) => candidate.targetId === filed.request.id,
    );
    expect(event?.detail["contactEmail"]).toBe("dev@example.org");
  });
});
