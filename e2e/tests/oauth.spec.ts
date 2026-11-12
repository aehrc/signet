/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * An OAuth / OpenID Connect endpoint securing a regular web app and its API.
 *
 * Everything else in this suite is SMART. This file proves the other kind of
 * endpoint against software that has never heard of SMART: oauth2-proxy, an
 * off-the-shelf OpenID Connect relying party, standing in front of a static app.
 * It signs a person in through Signet with the authorization code flow and PKCE,
 * and it validates the access tokens Signet mints for the API - signature, issuer
 * and audience - by itself, with no Signet-specific configuration.
 *
 * **The sign-in budget.** The browser journey below spends one end-user sign-in.
 * See `grants.spec.ts` for the whole budget; the other cases are plain requests.
 *
 * Author: John Grimes
 */

import { expect, test } from "@playwright/test";
import { decodeJwt } from "jose";

import { decideConsent, signIn } from "../support/launch.js";
import {
  NOTES_AUDIENCE,
  NOTES_ISSUER,
  NOTES_SEED,
  PROXY,
  ISSUER,
  SEED,
} from "../support/stack.js";

import type { APIRequestContext, APIResponse } from "@playwright/test";

/** The API resource behind oauth2-proxy. */
const NOTES_API = `${PROXY}/api/notes.json`;

/**
 * Asks a token endpoint for a client credentials token.
 *
 * @param request - Playwright's request context.
 * @param options - The request.
 * @param options.issuer - The endpoint to ask.
 * @param options.clientId - The client, which presents its secret with HTTP Basic.
 * @param options.secret - The client's secret.
 * @param options.scope - The scopes to request.
 * @param options.resource - An RFC 8707 resource indicator, if one is to be sent.
 * @returns The token endpoint's response.
 */
async function clientCredentials(
  request: APIRequestContext,
  options: {
    readonly issuer: string;
    readonly clientId: string;
    readonly secret: string;
    readonly scope: string;
    readonly resource?: string;
  },
): Promise<APIResponse> {
  const credential = Buffer.from(
    `${options.clientId}:${options.secret}`,
  ).toString("base64");
  return await request.post(`${options.issuer}/token`, {
    headers: { authorization: `Basic ${credential}` },
    form: {
      grant_type: "client_credentials",
      scope: options.scope,
      ...(options.resource === undefined ? {} : { resource: options.resource }),
    },
  });
}

/**
 * The OAuth `error` code in a refusal.
 *
 * @param response - The refusal.
 * @returns Its `error` member, or `undefined` if the body carries none.
 */
async function errorCode(response: APIResponse): Promise<unknown> {
  const body: unknown = await response.json();
  return typeof body === "object" && body !== null && "error" in body
    ? body.error
    : undefined;
}

/**
 * A `notes:read` token from the notes endpoint.
 *
 * @param request - Playwright's request context.
 * @returns The access token.
 */
async function notesToken(request: APIRequestContext): Promise<string> {
  const response = await clientCredentials(request, {
    issuer: NOTES_ISSUER,
    clientId: NOTES_SEED.serviceClientId,
    secret: NOTES_SEED.serviceSecret,
    scope: "notes:read",
  });
  expect(response.status()).toBe(200);
  const { access_token: accessToken } = (await response.json()) as {
    access_token: string;
  };
  return accessToken;
}

test.describe("a regular web app behind oauth2-proxy", () => {
  test("signs a person in through Signet and passes their email upstream", async ({
    page,
  }) => {
    // Visiting the app signed out sends the browser to Signet, because
    // oauth2-proxy discovered the notes endpoint and is configured to skip its own
    // sign-in button.
    await page.goto(`${PROXY}/`);
    await page.waitForURL((url) => url.href.startsWith(NOTES_ISSUER));
    await signIn(page, NOTES_SEED);

    // The consent screen describes the OpenID Connect scopes oauth2-proxy asked
    // for in words, not as scope strings.
    await expect(page.getByText("Confirm who you are")).toBeVisible();
    await expect(page.getByText("Know your name and username")).toBeVisible();
    await expect(page.getByText("Know your email address")).toBeVisible();
    await decideConsent(page, "Allow");

    // Back at the app, which oauth2-proxy now serves. The email shown is the one
    // oauth2-proxy took from Signet's ID token and passed upstream in
    // `X-Forwarded-Email`. oauth2-proxy refuses an unverified email by default, so
    // reaching this page also proves `email_verified` was released as true.
    await page.waitForURL((url) => url.href.startsWith(PROXY));
    await expect(page.getByRole("heading", { name: "Notes" })).toBeVisible();
    await expect(page.getByTestId("email")).toHaveText(NOTES_SEED.email);
  });
});

test.describe("an API behind oauth2-proxy", () => {
  test("refuses a request with no token", async ({ request }) => {
    const response = await request.get(NOTES_API, { maxRedirects: 0 });
    expect(response.status()).toBe(401);
  });

  test("accepts a client credentials token for the API's own scope", async ({
    request,
  }) => {
    const token = await notesToken(request);

    // No `resource` was sent, so the token is for the endpoint's audience. That
    // is the value oauth2-proxy checks `aud` against.
    const claims = decodeJwt(token);
    expect(claims.iss).toBe(NOTES_ISSUER);
    expect(claims.aud).toBe(NOTES_AUDIENCE);
    expect(claims["scope"]).toBe("notes:read");

    const response = await request.get(NOTES_API, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(response.status()).toBe(200);
    const body = (await response.json()) as {
      caller: string;
      notes: unknown[];
    };
    expect(body.notes).toHaveLength(1);
    // oauth2-proxy passed the token's subject upstream as the user.
    expect(body.caller).toBe(claims.sub);
  });

  test("refuses a token from a different issuer", async ({ request }) => {
    // A perfectly good token, from the SMART endpoint on the same Signet. Its
    // issuer and audience are not the ones oauth2-proxy trusts.
    const response = await clientCredentials(request, {
      issuer: ISSUER,
      clientId: SEED.backendClientId,
      secret: SEED.backendSecret,
      scope: "system/*.rs",
    });
    expect(response.status()).toBe(200);
    const { access_token: token } = (await response.json()) as {
      access_token: string;
    };

    const refused = await request.get(NOTES_API, {
      headers: { authorization: `Bearer ${token}` },
      maxRedirects: 0,
    });
    expect(refused.status()).toBe(403);
  });
});

test.describe("the notes endpoint", () => {
  test("mints a token for its own audience and refuses any other", async ({
    request,
  }) => {
    const options = {
      issuer: NOTES_ISSUER,
      clientId: NOTES_SEED.serviceClientId,
      secret: NOTES_SEED.serviceSecret,
      scope: "notes:read",
    };

    // Naming the endpoint's own audience is allowed, and changes nothing.
    const named = await clientCredentials(request, {
      ...options,
      resource: NOTES_AUDIENCE,
    });
    expect(named.status()).toBe(200);
    const { access_token: token } = (await named.json()) as {
      access_token: string;
    };
    expect(decodeJwt(token).aud).toBe(NOTES_AUDIENCE);

    // Naming any other is refused, rather than minting a token for an API this
    // endpoint does not protect.
    const other = await clientCredentials(request, {
      ...options,
      resource: "https://elsewhere.example.org/api",
    });
    expect(other.status()).toBe(400);
    expect(await errorCode(other)).toBe("invalid_target");
  });

  test("refuses a scope no grant rule names", async ({ request }) => {
    // `notes:write` is not in the client's allowlist or the policy, and an
    // unmatched scope is refused rather than ignored.
    const response = await clientCredentials(request, {
      issuer: NOTES_ISSUER,
      clientId: NOTES_SEED.serviceClientId,
      secret: NOTES_SEED.serviceSecret,
      scope: "notes:write",
    });
    expect(response.status()).toBe(400);
    expect(await errorCode(response)).toBe("invalid_scope");
  });

  test("publishes OpenID Connect discovery and no SMART configuration", async ({
    request,
  }) => {
    const openid = await request.get(
      `${NOTES_ISSUER}/.well-known/openid-configuration`,
    );
    expect(openid.status()).toBe(200);
    const document = (await openid.json()) as {
      issuer: string;
      scopes_supported: string[];
    };
    expect(document.issuer).toBe(NOTES_ISSUER);
    expect(document.scopes_supported).toEqual(
      expect.arrayContaining(["openid", "profile", "email"]),
    );

    const smart = await request.get(
      `${NOTES_ISSUER}/.well-known/smart-configuration`,
    );
    expect(smart.status()).toBe(404);
  });
});
