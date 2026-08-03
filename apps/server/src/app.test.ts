import { describe, expect, it } from "vitest";

import { createApp } from "./app.js";

describe("createApp", () => {
  it("serves a liveness probe", async () => {
    const response = await createApp().request("/healthz");
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ status: "ok" });
  });

  it("serves a readiness probe", async () => {
    const response = await createApp().request("/readyz");
    expect(response.status).toBe(200);
  });

  it("returns 404 for an unknown path", async () => {
    const response = await createApp().request("/nope");
    expect(response.status).toBe(404);
  });
});
