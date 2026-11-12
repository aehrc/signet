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
 * cannot be minted for an account that could not sign in with the password; and the
 * token never reaches the audit trail.
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
  let sequence = 0;

  beforeAll(async () => {
    stack = await createTestStack();
    owner = { cookie: await stack.signIn() };
  });

  afterAll(async () => {
    await stack.close();
  });

  /** Creates a local account with no password, as the console's invite flow does. */
  async function newAccount(): Promise<{ id: string; username: string }> {
    sequence += 1;
    const username = `invitee-${String(sequence)}`;
    const created = await adminJson<{
      user: { id: string; username: string; hasPassword: boolean };
    }>(stack, "POST", endpointPath(stack, "/users"), {
      credential: owner,
      body: { username, displayName: `Invitee ${String(sequence)}` },
      expect: 201,
    });
    expect(created.user.hasPassword).toBe(false);
    return created.user;
  }

  /** Mints an invitation for an account and returns the token from its link. */
  async function invite(userId: string): Promise<string> {
    const issued = await adminJson<IssuedInvitation>(
      stack,
      "POST",
      endpointPath(stack, `/users/${userId}/invitation`),
      { credential: owner, expect: 201 },
    );
    return new URL(issued.invitation.url).hash.slice(1);
  }

  /** Calls one of the invitation page's two API routes. */
  async function invitationApi(
    action: "details" | "accept",
    body: unknown,
    headers: Record<string, string> = {},
  ): Promise<Response> {
    return await stack.app.request(
      `${issuerPath(stack)}/invitation/${action}`,
      {
        method: "POST",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify(body),
      },
    );
  }

  /** Signs in at the management page and returns the response. */
  async function manageSignIn(
    username: string,
    password: string,
  ): Promise<Response> {
    return await stack.app.request(`${issuerPath(stack)}/manage/session`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
  }

  describe("issuing from the admin API", () => {
    it("creates a local account that cannot sign in until it has a password", async () => {
      const account = await newAccount();

      const response = await manageSignIn(account.username, "");
      expect(response.status).toBe(401);
    });

    it("returns a link under the endpoint's issuer, once, with a seven day expiry", async () => {
      const account = await newAccount();

      const response = await adminRequest(
        stack,
        "POST",
        endpointPath(stack, `/users/${account.id}/invitation`),
        { credential: owner },
      );
      expect(response.status).toBe(201);
      // The link is a credential: no cache between here and the console may keep it.
      expect(response.headers.get("cache-control")).toBe("no-store");
      const body = (await response.json()) as IssuedInvitation;

      expect(body.invitation.url).toMatch(
        new RegExp(`^${stack.issuer}/invitation#[A-Za-z0-9_-]{43}$`),
      );
      expect(
        Date.parse(body.invitation.expiresAt) - stack.context.clock().getTime(),
      ).toBe(INVITATION_TTL_SECONDS * 1000);

      // Reading it back reports the expiry and never the link.
      const read = await adminJson<{ invitation: Record<string, unknown> }>(
        stack,
        "GET",
        endpointPath(stack, `/users/${account.id}/invitation`),
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
        endpointPath(stack, `/users/${account.id}/invitation`),
        { credential: owner },
      );
      expect(read.invitation).toBeNull();
    });

    it("records the invitation in the audit trail without the token", async () => {
      const account = await newAccount();
      const token = await invite(account.id);

      const audit = await adminJson<{
        events: { action: string; targetId: string | null; detail: unknown }[];
      }>(stack, "GET", tenantPath(stack, "/audit?action=end-user.invited"), {
        credential: owner,
      });
      const event = audit.events.find(
        (candidate) => candidate.targetId === account.id,
      );
      expect(event).toBeDefined();
      expect(JSON.stringify(event)).not.toContain(token);
    });

    it("refuses a persona, which has no password to choose", async () => {
      const response = await adminRequest(
        stack,
        "POST",
        endpointPath(stack, `/users/${stack.persona.id}/invitation`),
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
        endpointPath(stack, `/users/${account.id}`),
        {
          credential: owner,
          body: { disabled: true },
        },
      );

      const response = await adminRequest(
        stack,
        "POST",
        endpointPath(stack, `/users/${account.id}/invitation`),
        { credential: owner },
      );
      expect(response.status).toBe(400);
    });

    it("refuses an endpoint that federates, which never checks a local password", async () => {
      await adminJson(stack, "POST", tenantPath(stack, "/endpoints"), {
        credential: owner,
        body: {
          slug: "federating",
          name: "Federating endpoint",
          fhirBaseUrl: "https://federating.test/fhir",
          authMode: "oidc",
        },
        expect: 201,
      });
      const account = await adminJson<{ user: { id: string } }>(
        stack,
        "POST",
        tenantPath(stack, "/endpoints/federating/users"),
        {
          credential: owner,
          body: { username: "federated", displayName: "Federated" },
          expect: 201,
        },
      );

      const response = await adminRequest(
        stack,
        "POST",
        tenantPath(
          stack,
          `/endpoints/federating/users/${account.user.id}/invitation`,
        ),
        { credential: owner },
      );
      expect(response.status).toBe(400);
      expect(await messageOf(response)).toMatch(/federates/);
    });

    it("lets a viewer see an invitation but not issue or cancel one", async () => {
      const account = await newAccount();
      const viewer: AdminCredential = {
        bearer: await stack.mintApiToken("viewer"),
      };
      const path = endpointPath(stack, `/users/${account.id}/invitation`);

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

    it("answers 404 for an account on another endpoint", async () => {
      const elsewhere = await adminJson<{ user: { id: string } }>(
        stack,
        "POST",
        tenantPath(stack, "/endpoints/federating/users"),
        {
          credential: owner,
          body: { username: "elsewhere", displayName: "Elsewhere" },
          expect: 201,
        },
      );

      const response = await adminRequest(
        stack,
        "POST",
        endpointPath(stack, `/users/${elsewhere.user.id}/invitation`),
        { credential: owner },
      );
      expect(response.status).toBe(404);
    });
  });

  describe("cancelling", () => {
    it("stops the link working, and says so when there is nothing to cancel", async () => {
      const account = await newAccount();
      const token = await invite(account.id);
      const path = endpointPath(stack, `/users/${account.id}/invitation`);

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
    it("names the account the link is for without spending it", async () => {
      const account = await newAccount();
      const token = await invite(account.id);

      const first = await invitationApi("details", { token });
      expect(first.status).toBe(200);
      expect(first.headers.get("cache-control")).toBe("no-store");
      expect(await first.json()).toMatchObject({
        username: account.username,
        endpointName: stack.endpoint.name,
      });
      expect((await invitationApi("details", { token })).status).toBe(200);
    });

    it("refuses an unknown token with the same answer as a spent one", async () => {
      const unknown = await invitationApi("details", { token: "not-a-token" });
      expect(unknown.status).toBe(404);
      expect(await unknown.json()).toMatchObject({
        error: "invalid_invitation",
      });
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
      expect(JSON.stringify(event)).not.toContain(token);
      expect(JSON.stringify(event)).not.toContain("a-chosen-password");
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
      const cookie = (signedIn.headers.get("set-cookie") ?? "").split(";", 1)[0];
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
        endpointPath(stack, `/users/${stack.user.id}/password`),
        { credential: owner, body: { password: TEST_PASSWORD } },
      );
    });

    it("refuses the link once the endpoint stops checking local passwords", async () => {
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
  });
});
