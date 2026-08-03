import { Hono } from "hono";
import { describe, expect, it } from "vitest";

import { createRateLimitStore, rateLimit, RATE_LIMITS } from "./rateLimit.js";

import type { RateLimitName } from "./rateLimit.js";

/** An app with one limited route, and a clock the test controls. */
function limitedApp(name: RateLimitName) {
  let now = new Date("2026-01-01T00:00:00Z");
  const store = createRateLimitStore();
  const app = new Hono();
  app.use(
    "/thing",
    rateLimit(name, () => now, store),
  );
  app.get("/thing", (c) => c.json({ ok: true }));

  return {
    app,
    store,
    setNow: (at: Date) => {
      now = at;
    },
    /** Makes a request as one address. */
    request: async (address = "203.0.113.7") =>
      await app.request("/thing", {
        headers: { "x-forwarded-for": address },
      }),
  };
}

describe("rateLimit", () => {
  it("admits up to the limit and then refuses", async () => {
    const harness = limitedApp("signIn");
    const statuses: number[] = [];
    for (let index = 0; index < RATE_LIMITS.signIn.limit + 2; index += 1) {
      statuses.push((await harness.request()).status);
    }
    expect(statuses.filter((status) => status === 200)).toHaveLength(
      RATE_LIMITS.signIn.limit,
    );
    expect(statuses.at(-1)).toBe(429);
  });

  it("counts each address separately", async () => {
    const harness = limitedApp("signIn");
    for (let index = 0; index < RATE_LIMITS.signIn.limit; index += 1) {
      await harness.request("203.0.113.7");
    }
    expect((await harness.request("203.0.113.7")).status).toBe(429);
    // A different caller is unaffected: an attacker must not be able to lock
    // everybody else out by exhausting one bucket.
    expect((await harness.request("198.51.100.4")).status).toBe(200);
  });

  it("answers a refusal with slow_down and Retry-After", async () => {
    const harness = limitedApp("signIn");
    let response = await harness.request();
    for (let index = 0; index < RATE_LIMITS.signIn.limit; index += 1) {
      response = await harness.request();
    }
    expect(response.status).toBe(429);
    expect(await response.json()).toMatchObject({ error: "slow_down" });
    expect(Number(response.headers.get("retry-after"))).toBeGreaterThan(0);
  });

  it("reports the limit and what remains on an admitted request", async () => {
    const harness = limitedApp("token");
    const response = await harness.request();
    expect(response.headers.get("ratelimit-limit")).toBe(
      String(RATE_LIMITS.token.limit),
    );
    expect(response.headers.get("ratelimit-remaining")).toBe(
      String(RATE_LIMITS.token.limit - 1),
    );
    expect(Number(response.headers.get("ratelimit-reset"))).toBeGreaterThan(0);
  });

  it("lets a caller through again once the windows have passed", async () => {
    const harness = limitedApp("signIn");
    for (let index = 0; index < RATE_LIMITS.signIn.limit + 5; index += 1) {
      await harness.request();
    }
    expect((await harness.request()).status).toBe(429);

    harness.setNow(new Date("2026-01-01T00:03:00Z"));
    expect((await harness.request()).status).toBe(200);
  });

  it("keys separately per limit name, so one route cannot exhaust another", async () => {
    let now = new Date("2026-01-01T00:00:00Z");
    const store = createRateLimitStore();
    const app = new Hono();
    app.use(
      "/sign-in",
      rateLimit("signIn", () => now, store),
    );
    app.use(
      "/token",
      rateLimit("token", () => now, store),
    );
    app.get("/sign-in", (c) => c.json({ ok: true }));
    app.get("/token", (c) => c.json({ ok: true }));

    const headers = { "x-forwarded-for": "203.0.113.7" };
    for (let index = 0; index < RATE_LIMITS.signIn.limit + 1; index += 1) {
      await app.request("/sign-in", { headers });
    }
    expect((await app.request("/sign-in", { headers })).status).toBe(429);
    expect((await app.request("/token", { headers })).status).toBe(200);
    // Referenced so the clock is not flagged as unused, and to document that the
    // two routes were exercised at the same instant.
    now = new Date(now);
  });

  it("collapses callers with no determinable address into one bucket", async () => {
    let now = new Date("2026-01-01T00:00:00Z");
    const store = createRateLimitStore();
    const app = new Hono();
    app.use(
      "/thing",
      rateLimit("signIn", () => now, store),
    );
    app.get("/thing", (c) => c.json({ ok: true }));

    // No `X-Forwarded-For` and no socket: the conservative choice is to limit
    // these together rather than exempt them.
    for (let index = 0; index < RATE_LIMITS.signIn.limit; index += 1) {
      await app.request("/thing");
    }
    expect((await app.request("/thing")).status).toBe(429);
    now = new Date(now);
  });
});

describe("createRateLimitStore", () => {
  it("forgets keys nobody has used, rather than growing forever", async () => {
    const harness = limitedApp("signIn");

    // Two hundred distinct addresses, which is the sweep interval.
    for (let index = 0; index < 200; index += 1) {
      await harness.request(`198.51.100.${String(index % 250)}`);
    }
    const before = harness.store.size();
    expect(before).toBeGreaterThan(0);

    // Two windows later, one more request sweeps everything stale.
    harness.setNow(new Date("2026-01-01T00:10:00Z"));
    for (let index = 0; index < 200; index += 1) {
      await harness.request("203.0.113.7");
    }
    expect(harness.store.size()).toBeLessThan(before);
  });
});
