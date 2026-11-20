/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Inviting an end user by link, from the admin API to the invitee's first sign-in.
 *
 * The properties asserted are the ones the feature is for and the ones that would make
 * it dangerous: a link lets exactly one person set exactly one account's password once;
 * it stops working when it expires, is replaced, is cancelled or has been used; it
 * cannot be minted for an account that could not sign in with the password anywhere;
 * and the token never reaches the audit trail.
 *
 * An invitation belongs to the tenant, as the account does: the link opens a tenant
 * page, and the password it sets works at every endpoint in local auth mode that the
 * account has been given access to.
 *
 * Author: John Grimes
 */

import { INVITATION_TTL_SECONDS } from "@signet/core";
import { afterAll, beforeAll, describe, expect, it } from "bun:test";

import {
  adminJson,
  adminRequest,
  endpointPath,
  tenantPath,
} from "../test/adminApi.js";
import { issuerPath } from "../test/flows.js";
import {
  createTestStack,
  TEST_PASSWORD,
  TEST_PUBLIC_URL,
  testDatabaseUrl,
} from "../test/harness.js";

import type { AdminCredential } from "../test/adminApi.js";
import type { TestStack } from "../test/harness.js";

/** What the admin API answers when an invitation is minted. */
interface IssuedInvitation {
  readonly invitation: {
    readonly url: string;
    readonly createdAt: string;
    readonly expiresAt: string;
  };
}

/** The `message` of an admin API error body, or an empty string. */
async function messageOf(response: Response): Promise<string> {
  const body: unknown = await response.json();
  return typeof body === "object" &&
    body !== null &&
    "message" in body &&
    typeof body.message === "string"
    ? body.message
    : "";
}

describe.skipIf(testDatabaseUrl === undefined)("end user invitations", () => {
  let stack: TestStack;
  let owner: AdminCredential;
  let federating: TestStack;
  let sequence = 0;

  beforeAll(async () => {
    stack = await createTestStack();
    owner = { cookie: await stack.signIn() };
    federating = await stack.addEndpoint({
      slug: "federating",
      endpoint: { authMode: "oidc" },
    });
  });

  afterAll(async () => {
    await stack.close();
  });

  /** Creates a tenant account with no password and no access. */
  async function newBareAccount(): Promise<{ id: string; username: string }> {
    sequence += 1;
    const username = `invitee-${String(sequence)}`;
    const created = await adminJson<{
      user: { id: string; username: string; hasPassword: boolean };
    }>(stack, "POST", tenantPath(stack, "/users"), {
      credential: owner,
      body: { username, displayName: `Invitee ${String(sequence)}` },
      expect: 201,
    });
    expect(created.user.hasPassword).toBe(false);
    return created.user;
  }

  /** Gives an account access to an endpoint. */
  async function grant(at: TestStack, userId: string): Promise<void> {
    await adminJson(stack, "PUT", endpointPath(at, `/users/${userId}`), {
      credential: owner,
      body: {},
    });
  }

  /**
   * Creates an account with access to the fixture endpoint, as the console's invite
   * flow leaves it.
   */
  async function newAccount(): Promise<{ id: string; username: string }> {
    const account = await newBareAccount();
    await grant(stack, account.id);
    return account;
  }

  /** The admin API path of an account's invitation. */
  function invitationPath(userId: string): string {
    return tenantPath(stack, `/users/${userId}/invitation`);
  }

  /** Mints an invitation for an account and returns the token from its link. */
  async function invite(userId: string): Promise<string> {
    const issued = await adminJson<IssuedInvitation>(
      stack,
      "POST",
      invitationPath(userId),
      { credential: owner, expect: 201 },
    );
    return new URL(issued.invitation.url).hash.slice(1);
  }

  /** Calls one of the invitation page's two API routes. */
  async function invitationApi(
    action: "details" | "accept",
    body: unknown,
  ): Promise<Response> {
    return await stack.app.request(
      `/t/${stack.tenant.slug}/invitation/${action}`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      },
    );
  }

  /** Signs in at an endpoint's management page and returns the response. */
  async function manageSignIn(
    username: string,
    password: string,
    at: TestStack = stack,
  ): Promise<Response> {
    return await stack.app.request(`${issuerPath(at)}/manage/session`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
  }

  describe("links issued before invitations moved to the tenant", () => {
    it("redirects the endpoint's old invitation page to the tenant's", async () => {
      // Links already emailed point at `{iss}/invitation#token`. The browser keeps
      // the fragment across a redirect, so the token reaches the tenant page.
      const response = await stack.app.request(
        `${issuerPath(stack)}/invitation`,
      );
      expect(response.status).toBe(308);
      expect(response.headers.get("location")).toBe(
        `/t/${stack.tenant.slug}/invitation`,
      );
    });
  });

  describe("issuing from the admin API", () => {
    it("creates a local account that cannot sign in until it has a password", async () => {
      const account = await newAccount();

      const response = await manageSignIn(account.username, "");
      expect(response.status).toBe(401);
    });

    it("returns a link to the tenant's invitation page, once, with a seven day expiry", async () => {
      const account = await newAccount();

      const response = await adminRequest(
        stack,
        "POST",
        invitationPath(account.id),
        { credential: owner },
      );
      expect(response.status).toBe(201);
      // The link is a credential: no cache between here and the console may keep it.
      expect(response.headers.get("cache-control")).toBe("no-store");
      const body = (await response.json()) as IssuedInvitation;

      expect(body.invitation.url).toMatch(
        new RegExp(
          `^${TEST_PUBLIC_URL}/t/${stack.tenant.slug}/invitation#[A-Za-z0-9_-]{43}$`,
        ),
      );
      expect(
        Date.parse(body.invitation.expiresAt) - stack.context.clock().getTime(),
      ).toBe(INVITATION_TTL_SECONDS * 1000);

      // Reading it back reports the expiry and never the link.
      const read = await adminJson<{ invitation: Record<string, unknown> }>(
        stack,
        "GET",
        invitationPath(account.id),
        { credential: owner },
      );
      expect(read.invitation).toEqual({
        createdAt: body.invitation.createdAt,
        expiresAt: body.invitation.expiresAt,
      });
    });

    it("reports no invitation for an account that has none", async () => {
      const account = await newAccount();

      const read = await adminJson<{ invitation: unknown }>(
        stack,
        "GET",
        invitationPath(account.id),
        { credential: owner },
      );
      expect(read.invitation).toBeNull();
    });

    it("records the invitation in the audit trail without the token", async () => {
      const account = await newAccount();
      const token = await invite(account.id);

      const audit = await adminJson<{
        events: {
          targetId: string | null;
          endpointId: string | null;
          detail: unknown;
        }[];
      }>(stack, "GET", tenantPath(stack, "/audit?action=end-user.invited"), {
        credential: owner,
      });
      const event = audit.events.find(
        (candidate) => candidate.targetId === account.id,
      );
      expect(event).toBeDefined();
      expect(event?.endpointId).toBeNull();
      expect(JSON.stringify(event)).not.toContain(token);
    });

    it("refuses a persona, which has no password to choose", async () => {
      const response = await adminRequest(
        stack,
        "POST",
        invitationPath(stack.persona.id),
        { credential: owner },
      );
      expect(response.status).toBe(400);
      expect(await messageOf(response)).toMatch(/persona/i);
    });

    it("refuses a disabled account, which could not sign in", async () => {
      const account = await newAccount();
      await adminJson(
        stack,
        "PATCH",
        tenantPath(stack, `/users/${account.id}`),
        {
          credential: owner,
          body: { disabled: true },
        },
      );

      const response = await adminRequest(
        stack,
        "POST",
        invitationPath(account.id),
        { credential: owner },
      );
      expect(response.status).toBe(400);
      expect(await messageOf(response)).toMatch(/disabled/);
    });

    it("refuses an account whose only endpoints federate, or that has none", async () => {
      const account = await newBareAccount();
      const withNothing = await adminRequest(
        stack,
        "POST",
        invitationPath(account.id),
        { credential: owner },
      );
      expect(withNothing.status).toBe(400);
      expect(await messageOf(withNothing)).toMatch(/local auth mode/);

      await grant(federating, account.id);
      const federatedOnly = await adminRequest(
        stack,
        "POST",
        invitationPath(account.id),
        { credential: owner },
      );
      expect(federatedOnly.status).toBe(400);
      expect(await messageOf(federatedOnly)).toMatch(/local auth mode/);

      // One endpoint that checks a password is enough.
      await grant(stack, account.id);
      expect(
        (
          await adminRequest(stack, "POST", invitationPath(account.id), {
            credential: owner,
          })
        ).status,
      ).toBe(201);
    });

    it("lets a viewer see an invitation but not issue or cancel one", async () => {
      const account = await newAccount();
      const viewer: AdminCredential = {
        bearer: await stack.mintApiToken("viewer"),
      };
      const path = invitationPath(account.id);

      expect(
        (await adminRequest(stack, "GET", path, { credential: viewer })).status,
      ).toBe(200);
      expect(
        (await adminRequest(stack, "POST", path, { credential: viewer }))
          .status,
      ).toBe(403);
      expect(
        (await adminRequest(stack, "DELETE", path, { credential: viewer }))
          .status,
      ).toBe(403);
    });

    it("answers 404 for an account the tenant does not hold", async () => {
      const response = await adminRequest(
        stack,
        "POST",
        invitationPath("00000000-0000-4000-8000-000000000000"),
        { credential: owner },
      );
      expect(response.status).toBe(404);
    });
  });

  describe("cancelling", () => {
    it("stops the link working, and says so when there is nothing to cancel", async () => {
      const account = await newAccount();
      const token = await invite(account.id);
      const path = invitationPath(account.id);

      expect(
        (await adminRequest(stack, "DELETE", path, { credential: owner }))
          .status,
      ).toBe(204);
      expect((await invitationApi("details", { token })).status).toBe(404);
      expect(
        (await adminRequest(stack, "DELETE", path, { credential: owner }))
          .status,
      ).toBe(404);
    });
  });

  describe("the invitation page's API", () => {
    it("names the account and the tenant the link is for without spending it", async () => {
      const account = await newAccount();
      const token = await invite(account.id);

      const first = await invitationApi("details", { token });
      expect(first.status).toBe(200);
      expect(first.headers.get("cache-control")).toBe("no-store");
      const details = (await first.json()) as Record<string, unknown>;
      expect(details).toMatchObject({
        username: account.username,
        tenantName: stack.tenant.name,
      });
      expect(Object.keys(details)).not.toContain("endpointName");
      expect((await invitationApi("details", { token })).status).toBe(200);
    });

    it("refuses an unknown token with the same answer as a spent one", async () => {
      const unknown = await invitationApi("details", { token: "not-a-token" });
      expect(unknown.status).toBe(404);
      expect(await unknown.json()).toMatchObject({
        error: "invalid_invitation",
      });
    });

    it("answers 404 for a tenant that does not exist", async () => {
      const response = await stack.app.request(
        "/t/no-such-tenant/invitation/details",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ token: "not-a-token" }),
        },
      );
      expect(response.status).toBe(404);
    });

    it("refuses a link presented to another tenant", async () => {
      const other = await createTestStack();
      try {
        const account = await newAccount();
        const token = await invite(account.id);
        const response = await other.app.request(
          `/t/${other.tenant.slug}/invitation/details`,
          {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ token }),
          },
        );
        expect(response.status).toBe(404);
      } finally {
        await other.close();
      }
    });

    it("refuses a malformed body", async () => {
      expect((await invitationApi("details", { token: 7 })).status).toBe(400);
      expect(
        (await invitationApi("accept", { token: "abc", password: 7 })).status,
      ).toBe(400);
    });

    it("sets the password once, after which the invitee can sign in", async () => {
      const account = await newAccount();
      const token = await invite(account.id);

      const accepted = await invitationApi("accept", {
        token,
        password: "a-chosen-password",
      });
      expect(accepted.status).toBe(200);
      expect(await accepted.json()).toEqual({ username: account.username });

      expect(
        (await manageSignIn(account.username, "a-chosen-password")).status,
      ).toBe(200);

      // Spent: neither half of the page's API recognises it any more.
      expect(
        (
          await invitationApi("accept", {
            token,
            password: "a-second-password",
          })
        ).status,
      ).toBe(404);
      expect((await invitationApi("details", { token })).status).toBe(404);

      const audit = await adminJson<{
        events: {
          actorType: string;
          actorId: string | null;
          endpointId: string | null;
          detail: unknown;
        }[];
      }>(
        stack,
        "GET",
        tenantPath(stack, "/audit?action=end-user.invitation-accepted"),
        { credential: owner },
      );
      const event = audit.events.find(
        (candidate) => candidate.actorId === account.id,
      );
      expect(event?.actorType).toBe("end-user");
      expect(event?.endpointId).toBeNull();
      expect(JSON.stringify(event)).not.toContain(token);
      expect(JSON.stringify(event)).not.toContain("a-chosen-password");
    });

    it("sets the one password every local endpoint the account can use checks", async () => {
      const second = await stack.addEndpoint({ slug: "second-local" });
      const account = await newAccount();
      await grant(second, account.id);
      await grant(federating, account.id);
      const token = await invite(account.id);

      expect(
        (
          await invitationApi("accept", {
            token,
            password: "one-password-for-all",
          })
        ).status,
      ).toBe(200);

      expect(
        (await manageSignIn(account.username, "one-password-for-all", stack))
          .status,
      ).toBe(200);
      expect(
        (await manageSignIn(account.username, "one-password-for-all", second))
          .status,
      ).toBe(200);
    });

    it("invites an account with access to an OAuth endpoint, keeping its email", async () => {
      // Nothing about an invitation is SMART-specific: it sets a password and no
      // more, so the account keeps the fields it was given.
      const api = await stack.addEndpoint({
        slug: "invite-oauth",
        kind: "oauth",
      });
      const created = await adminJson<{ user: { id: string } }>(
        stack,
        "POST",
        tenantPath(stack, "/users"),
        {
          credential: owner,
          body: {
            username: "api-invitee",
            displayName: "API Invitee",
            email: "api-invitee@example.org",
            emailVerified: true,
          },
          expect: 201,
        },
      );
      await grant(api, created.user.id);
      const token = await invite(created.user.id);

      expect(
        (
          await invitationApi("accept", {
            token,
            password: "a-chosen-password",
          })
        ).status,
      ).toBe(200);

      const after = await adminJson<{
        user: { hasPassword: boolean; email: string; emailVerified: boolean };
      }>(stack, "GET", tenantPath(stack, `/users/${created.user.id}`), {
        credential: owner,
      });
      expect(after.user).toMatchObject({
        hasPassword: true,
        email: "api-invitee@example.org",
        emailVerified: true,
      });
    });

    it("refuses a password outside the bounds without spending the link", async () => {
      const account = await newAccount();
      const token = await invite(account.id);

      const refused = await invitationApi("accept", {
        token,
        password: "short",
      });
      expect(refused.status).toBe(400);
      expect((await invitationApi("details", { token })).status).toBe(200);
    });

    it("honours only the newest link when a second is issued", async () => {
      const account = await newAccount();
      const first = await invite(account.id);
      const second = await invite(account.id);

      expect((await invitationApi("details", { token: first })).status).toBe(
        404,
      );
      expect((await invitationApi("details", { token: second })).status).toBe(
        200,
      );
    });

    it("stops working once the seven days have passed", async () => {
      const account = await newAccount();
      const token = await invite(account.id);
      const issuedAt = stack.context.clock();

      stack.setNow(
        new Date(issuedAt.getTime() + INVITATION_TTL_SECONDS * 1000 + 1000),
      );
      try {
        expect((await invitationApi("details", { token })).status).toBe(404);
        expect(
          (
            await invitationApi("accept", {
              token,
              password: "too-late-password",
            })
          ).status,
        ).toBe(404);
      } finally {
        stack.setNow(issuedAt);
      }
    });

    it("resets an existing password and ends the sessions the old one opened", async () => {
      // The harness's clinician already has a password; a link replaces it.
      const signedIn = await manageSignIn(stack.user.username, TEST_PASSWORD);
      expect(signedIn.status).toBe(200);
      const cookie = (signedIn.headers.get("set-cookie") ?? "").split(
        ";",
        1,
      )[0];
      const token = await invite(stack.user.id);

      expect(
        (
          await invitationApi("accept", {
            token,
            password: "a-replacement-password",
          })
        ).status,
      ).toBe(200);

      const stale = await stack.app.request(
        `${issuerPath(stack)}/manage/authorizations`,
        { headers: { cookie: cookie ?? "" } },
      );
      expect(stale.status).toBe(401);
      expect(
        (await manageSignIn(stack.user.username, TEST_PASSWORD)).status,
      ).toBe(401);
      expect(
        (await manageSignIn(stack.user.username, "a-replacement-password"))
          .status,
      ).toBe(200);

      // Restored, so the rest of the suite's fixture is as it found it.
      await adminRequest(
        stack,
        "POST",
        tenantPath(stack, `/users/${stack.user.id}/password`),
        { credential: owner, body: { password: TEST_PASSWORD } },
      );
    });

    it("refuses the link once no endpoint the account can use checks local passwords", async () => {
      const account = await newAccount();
      const token = await invite(account.id);

      await adminJson(stack, "PATCH", endpointPath(stack), {
        credential: owner,
        body: { authMode: "oidc" },
      });
      try {
        expect((await invitationApi("details", { token })).status).toBe(404);
        expect(
          (
            await invitationApi("accept", {
              token,
              password: "a-chosen-password",
            })
          ).status,
        ).toBe(404);
      } finally {
        await adminJson(stack, "PATCH", endpointPath(stack), {
          credential: owner,
          body: { authMode: "local" },
        });
      }
      expect((await invitationApi("details", { token })).status).toBe(200);
    });

    it("refuses the link once the account's access is withdrawn everywhere", async () => {
      const account = await newAccount();
      const token = await invite(account.id);

      await adminRequest(
        stack,
        "DELETE",
        endpointPath(stack, `/users/${account.id}`),
        {
          credential: owner,
        },
      );
      expect((await invitationApi("details", { token })).status).toBe(404);
      expect(
        (
          await invitationApi("accept", {
            token,
            password: "a-chosen-password",
          })
        ).status,
      ).toBe(404);
    });
  });
});
