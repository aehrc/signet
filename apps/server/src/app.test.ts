import { describe, expect, it, vi } from "vitest";

import { createApp } from "./app.js";

import type { ServerContext } from "./context.js";

/**
 * A context whose database does nothing but answer the readiness ping.
 *
 * The OAuth routes all resolve an endpoint first and are covered by the integration
 * suites against a real database. What is asserted here is the composition around
 * them: that the probes exist, that readiness actually consults the database, and
 * that an unrouted path is a 404 rather than being swallowed by the issuer prefix.
 */
function contextWith(execute: () => Promise<unknown>): ServerContext {
  return {
    config: {
      port: 3000,
      publicUrl: "https://signet.example.org",
      databaseUrl: "postgres://unused",
      masterKey: "0123456789abcdef0123456789abcdef",
      logLevel: "error",
      webRoot: undefined,
      allowPrivateOutboundFetches: false,
    },
    db: { execute } as unknown as ServerContext["db"],
    audit: { record: () => Promise.resolve() },
    clock: () => new Date(0),
  };
}

describe("createApp", () => {
  it("serves a liveness probe without touching the database", async () => {
    const execute = vi.fn(() => Promise.resolve());
    const response = await createApp(contextWith(execute)).request("/healthz");

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ status: "ok" });
    expect(execute).not.toHaveBeenCalled();
  });

  it("serves a readiness probe that checks the database", async () => {
    const execute = vi.fn(() => Promise.resolve());
    const response = await createApp(contextWith(execute)).request("/readyz");

    expect(response.status).toBe(200);
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it("reports 503 when the database is unreachable", async () => {
    const response = await createApp(
      contextWith(() => Promise.reject(new Error("ECONNREFUSED"))),
    ).request("/readyz");

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({
      status: "unavailable",
      database: "unreachable",
    });
  });

  it("returns 404 for an unknown path", async () => {
    const response = await createApp(
      contextWith(() => Promise.resolve()),
    ).request("/nope");
    expect(response.status).toBe(404);
  });
});
