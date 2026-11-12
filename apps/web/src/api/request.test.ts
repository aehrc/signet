/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * How a request body reaches the wire: JSON for a value, the bytes themselves for a
 * file, which is how a logo is uploaded.
 *
 * Author: John Grimes
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test";

import { requestJson } from "./request.js";

/** What the stubbed `fetch` was called with. */
let sent: { body: unknown; headers: Record<string, string> } | undefined;
const realFetch = globalThis.fetch;

beforeEach(() => {
  sent = undefined;
  globalThis.fetch = ((_input: unknown, init?: RequestInit) => {
    sent = {
      body: init?.body,
      headers: init?.headers as Record<string, string>,
    };
    return Promise.resolve(Response.json({ ok: true }));
  }) as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

describe("requestJson", () => {
  it("serialises a plain value as JSON", async () => {
    await requestJson("/x", { method: "POST", body: { name: "Acme" } });
    expect(sent?.body).toBe('{"name":"Acme"}');
    expect(sent?.headers["content-type"]).toBe("application/json");
  });

  it("sends a file as it is, typed as the file is", async () => {
    const file = new Blob(["<svg></svg>"], { type: "image/svg+xml" });
    await requestJson("/x", { method: "PUT", body: file });
    expect(sent?.body).toBe(file);
    expect(sent?.headers["content-type"]).toBe("image/svg+xml");
  });

  it("types a file of unknown type as bytes rather than as JSON", async () => {
    await requestJson("/x", { method: "PUT", body: new Blob(["?"]) });
    expect(sent?.headers["content-type"]).toBe("application/octet-stream");
  });
});
