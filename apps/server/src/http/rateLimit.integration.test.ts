/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The rate limits, applied to the real routes.
 *
 * The middleware's own arithmetic is tested in `./rateLimit.test.ts`. What this
 * suite asserts is that it is attached where it was meant to be and nowhere else -
 * which is the half that a refactor breaks silently, because a route with no
 * limiter behaves exactly like one with a limiter nobody has reached yet.
 *
 * The stack opts the limiter in, which every other suite opts out of.
 *
 * Author: John Grimes
 */

import { afterAll, beforeAll, describe, expect, it } from "bun:test";

import { RATE_LIMITS } from "./rateLimit.js";
import { adminRequest } from "../test/adminApi.js";
import { issuerPath, postForm } from "../test/flows.js";
import {
  createTestStack,
  TEST_PASSWORD,
  testDatabaseUrl,
} from "../test/harness.js";

import type { TestStack } from "../test/harness.js";

/** An address nobody else in the suite is using. */
const CALLER = { "x-forwarded-for": "203.0.113.42" };

describe.skipIf(testDatabaseUrl === undefined)("the rate limits", () => {
  let stack: TestStack;

  beforeAll(async () => {
    stack = await createTestStack({
      rateLimits: "enforced",
      trustedProxyCount: 1,
    });
  });

  afterAll(async () => {
    await stack.close();
  });

  /** Signs in to the console as one address, and returns the status. */
  async function adminSignIn(address: string): Promise<number> {
    const response = await stack.app.request("/api/v1/session", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": address,
      },
      body: JSON.stringify({
        email: stack.admin.email,
        // Wrong on purpose: the limit must apply to failures, since guessing is
        // what it is there to stop.
        password: "not the password",
      }),
    });
    return response.status;
  }

  it("refuses admin sign-in after too many attempts from one address", async () => {
    const statuses: number[] = [];
    for (let index = 0; index < RATE_LIMITS.signIn.limit + 1; index += 1) {
      statuses.push(await adminSignIn("203.0.113.10"));
    }
    // Every attempt before the last was refused as a bad credential, not as a
    // rate-limit failure: the limiter must not fire early.
    expect(statuses.slice(0, RATE_LIMITS.signIn.limit)).not.toContain(429);
    expect(statuses.at(-1)).toBe(429);
  });

  it("leaves another address alone", async () => {
    for (let index = 0; index < RATE_LIMITS.signIn.limit + 1; index += 1) {
      await adminSignIn("203.0.113.11");
    }
    expect(await adminSignIn("203.0.113.12")).not.toBe(429);
  });

  it("does not limit signing out, only signing in", async () => {
    const cookie = await stack.signIn();
    for (let index = 0; index < RATE_LIMITS.signIn.limit + 1; index += 1) {
      await adminSignIn("203.0.113.13");
    }
    const response = await stack.app.request("/api/v1/session", {
      method: "DELETE",
      headers: { cookie, "x-forwarded-for": "203.0.113.13" },
    });
    expect(response.status).not.toBe(429);
  });

  it("limits the token endpoint", async () => {
    let last = 0;
    for (let index = 0; index < RATE_LIMITS.token.limit + 1; index += 1) {
      const response = await postForm(
        stack,
        "/token",
        { grant_type: "authorization_code", code: "nope" },
        CALLER,
      );
      last = response.status;
    }
    expect(last).toBe(429);
  });

  it("answers a refused token request with slow_down and Retry-After", async () => {
    let response = await postForm(
      stack,
      "/token",
      { grant_type: "authorization_code", code: "nope" },
      { "x-forwarded-for": "203.0.113.50" },
    );
    for (let index = 0; index < RATE_LIMITS.token.limit; index += 1) {
      response = await postForm(
        stack,
        "/token",
        { grant_type: "authorization_code", code: "nope" },
        { "x-forwarded-for": "203.0.113.50" },
      );
    }
    expect(response.status).toBe(429);
    expect(await response.json()).toMatchObject({ error: "slow_down" });
    expect(Number(response.headers.get("retry-after"))).toBeGreaterThan(0);
  });

  it("limits /authorize", async () => {
    let last = 0;
    for (let index = 0; index < RATE_LIMITS.authorize.limit + 1; index += 1) {
      const response = await stack.app.request(
        `${issuerPath(stack)}/authorize?response_type=code`,
        { headers: { "x-forwarded-for": "203.0.113.60" } },
      );
      last = response.status;
    }
    expect(last).toBe(429);
  });

  it("does not limit discovery, which every client fetches", async () => {
    let last = 0;
    for (let index = 0; index < RATE_LIMITS.authorize.limit + 5; index += 1) {
      const response = await stack.app.request(
        `${issuerPath(stack)}/.well-known/smart-configuration`,
        { headers: { "x-forwarded-for": "203.0.113.70" } },
      );
      last = response.status;
    }
    expect(last).toBe(200);
  });

  it("limits /introspect, /revoke and /launch-context like the token endpoint", async () => {
    // All three verify a client secret through the same Argon2id path /token
    // uses, so secret guessing pays there exactly as it does at /token.
    for (const route of ["/introspect", "/revoke", "/launch-context"]) {
      let last = 0;
      for (let index = 0; index < RATE_LIMITS.token.limit + 1; index += 1) {
        const response = await postForm(
          stack,
          route,
          { token: "nope", client_id: "nope", client_secret: "nope" },
          { "x-forwarded-for": `203.0.113.2${route.length}` },
        );
        last = response.status;
      }
      expect(last).toBe(429);
    }
  });

  it("limits anonymous client registration requests", async () => {
    let last = 0;
    for (
      let index = 0;
      index < RATE_LIMITS.clientRequest.limit + 1;
      index += 1
    ) {
      const response = await stack.app.request(
        `${issuerPath(stack)}/apps/requests`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": "203.0.113.21",
          },
          body: JSON.stringify({
            name: "Queue Filler",
            clientType: "public",
            redirectUris: ["https://app.example.org/callback"],
            requestedScopes: ["openid"],
            contactEmail: "dev@example.org",
          }),
        },
      );
      last = response.status;
    }
    expect(last).toBe(429);
  });

  it("limits the federation round trip", async () => {
    // The limiter is attached ahead of the handler, so it fires on an endpoint
    // that does not even federate - the posture /register already takes.
    let last = 0;
    for (let index = 0; index < RATE_LIMITS.federation.limit + 1; index += 1) {
      const response = await stack.app.request(
        `${issuerPath(stack)}/federation/start`,
        { headers: { "x-forwarded-for": "203.0.113.22" } },
      );
      last = response.status;
    }
    expect(last).toBe(429);
  });

  it("does not limit the admin API's reads", async () => {
    const cookie = await stack.signIn();
    let last = 0;
    for (let index = 0; index < RATE_LIMITS.signIn.limit + 5; index += 1) {
      const response = await adminRequest(stack, "GET", "/api/v1/session", {
        credential: { cookie },
      });
      last = response.status;
    }
    // A console page that polls must not be throttled into failure by a limit
    // that exists for password guessing.
    expect(last).toBe(200);
  });

  it("limits the end user's management sign-in", async () => {
    let last = 0;
    for (let index = 0; index < RATE_LIMITS.signIn.limit + 1; index += 1) {
      const response = await stack.app.request(
        `${issuerPath(stack)}/manage/session`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": "203.0.113.80",
          },
          body: JSON.stringify({
            username: "clinician",
            password: TEST_PASSWORD,
          }),
        },
      );
      last = response.status;
    }
    expect(last).toBe(429);
  });

  it("does not let one sign-in surface exhaust another's allowance", async () => {
    // Exhaust the management sign-in from an address.
    let last = 0;
    for (let index = 0; index < RATE_LIMITS.signIn.limit + 1; index += 1) {
      const response = await stack.app.request(
        `${issuerPath(stack)}/manage/session`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": "203.0.113.90",
          },
          body: JSON.stringify({ username: "clinician", password: "wrong" }),
        },
      );
      last = response.status;
    }
    expect(last).toBe(429);

    // The console's sign-in is a different route and must still answer. Sharing
    // one bucket across every route that checks a password means an
    // unauthenticated caller can lock the operators out of the console by
    // guessing at an end user's management page - the same "exhaust somebody
    // else's allowance" failure the key is supposed to prevent.
    expect(await adminSignIn("203.0.113.90")).not.toBe(429);
  });

  it("still limits each surface on its own", async () => {
    // The separation must not become an exemption: having spent the management
    // allowance above, the console's own allowance must still run out.
    for (let index = 0; index < RATE_LIMITS.signIn.limit + 1; index += 1) {
      await adminSignIn("203.0.113.91");
    }
    expect(await adminSignIn("203.0.113.91")).toBe(429);
  });
});
