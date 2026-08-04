/**
 * Author: John Grimes
 */

import { describe, expect, it, vi } from "vitest";

import {
  checkOutboundUrl,
  fetchGuardedJson,
  DEFAULT_OUTBOUND_MAX_BYTES,
} from "./outboundFetch.js";

describe("checkOutboundUrl", () => {
  it("accepts an https URL with a DNS name", () => {
    const result = checkOutboundUrl("https://app.example.org/jwks.json");
    expect(result.ok).toBe(true);
  });

  it("accepts an https URL with a public IP literal", () => {
    expect(checkOutboundUrl("https://93.184.216.34/jwks").ok).toBe(true);
  });

  it("refuses a value that is not a URL", () => {
    expect(checkOutboundUrl("not a url")).toMatchObject({
      reason: "not-a-url",
    });
  });

  it("refuses plain HTTP by default", () => {
    expect(checkOutboundUrl("http://app.example.org/jwks")).toMatchObject({
      reason: "insecure-scheme",
    });
  });

  it("permits plain HTTP when private addresses are allowed", () => {
    expect(checkOutboundUrl("http://keycloak:8080/jwks", true).ok).toBe(true);
  });

  it.each([
    "file:///etc/passwd",
    "gopher://example.org/",
    "ftp://example.org/",
  ])("refuses %s", (value) => {
    expect(checkOutboundUrl(value)).toMatchObject({
      reason: "insecure-scheme",
    });
  });

  it("refuses userinfo", () => {
    expect(
      checkOutboundUrl("https://user:pass@app.example.org/jwks"),
    ).toMatchObject({ reason: "userinfo" });
    expect(
      checkOutboundUrl("https://metadata@169.254.169.254/jwks"),
    ).toMatchObject({ reason: "userinfo" });
  });

  it.each([
    "https://127.0.0.1/jwks",
    "https://10.0.0.1/jwks",
    "https://169.254.169.254/latest/meta-data/",
    "https://[::1]/jwks",
    "https://[::ffff:127.0.0.1]/jwks",
  ])("refuses the private literal in %s", (value) => {
    expect(checkOutboundUrl(value)).toMatchObject({
      reason: "blocked-address",
    });
  });

  it("permits a private literal when explicitly allowed", () => {
    expect(checkOutboundUrl("https://10.0.0.1/jwks", true).ok).toBe(true);
  });
});

/** A `fetch` that answers with a JSON body and never touches the network. */
function jsonFetch(body: unknown, status = 200): typeof fetch {
  return vi.fn(() =>
    Promise.resolve(
      Response.json(body, {
        status,
        headers: { "content-type": "application/json" },
      }),
    ),
  );
}

describe("fetchGuardedJson", () => {
  const publicResolve = () => Promise.resolve(["93.184.216.34"]);

  it("returns the parsed document", async () => {
    const result = await fetchGuardedJson<{ keys: unknown[] }>(
      "https://app.example.org/jwks",
      { resolve: publicResolve, fetchImpl: jsonFetch({ keys: [] }) },
    );
    expect(result).toEqual({ ok: true, value: { keys: [] } });
  });

  it("refuses before fetching when the URL fails the syntax check", async () => {
    const fetchImpl = jsonFetch({});
    const result = await fetchGuardedJson("http://app.example.org/jwks", {
      resolve: publicResolve,
      fetchImpl,
    });
    expect(result).toMatchObject({ reason: "insecure-scheme" });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("refuses a name resolving to a private address", async () => {
    const fetchImpl = jsonFetch({});
    const result = await fetchGuardedJson("https://localtest.me/jwks", {
      resolve: () => Promise.resolve(["127.0.0.1"]),
      fetchImpl,
    });
    expect(result).toMatchObject({ reason: "blocked-address" });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("refuses when any one of several addresses is private", async () => {
    const result = await fetchGuardedJson("https://mixed.example.org/jwks", {
      resolve: () => Promise.resolve(["93.184.216.34", "10.0.0.1"]),
      fetchImpl: jsonFetch({}),
    });
    expect(result).toMatchObject({ reason: "blocked-address" });
  });

  it("refuses a name that does not resolve", async () => {
    const result = await fetchGuardedJson("https://nowhere.example/jwks", {
      resolve: () => Promise.reject(new Error("ENOTFOUND")),
      fetchImpl: jsonFetch({}),
    });
    expect(result).toMatchObject({ reason: "unresolvable" });
  });

  it("refuses a name that resolves to nothing", async () => {
    const result = await fetchGuardedJson("https://nowhere.example/jwks", {
      resolve: () => Promise.resolve([]),
      fetchImpl: jsonFetch({}),
    });
    expect(result).toMatchObject({ reason: "unresolvable" });
  });

  it("skips resolution when private addresses are allowed", async () => {
    const resolve = vi.fn(() => Promise.resolve(["10.0.0.1"]));
    const result = await fetchGuardedJson("http://keycloak:8080/jwks", {
      allowPrivateAddresses: true,
      resolve,
      fetchImpl: jsonFetch({ ok: 1 }),
    });
    expect(result.ok).toBe(true);
    expect(resolve).not.toHaveBeenCalled();
  });

  it("reports a refused redirect distinctly from a connection failure", async () => {
    const result = await fetchGuardedJson("https://app.example.org/jwks", {
      resolve: publicResolve,
      fetchImpl: (() =>
        Promise.reject(
          new TypeError("fetch failed: unexpected redirect"),
        )) as unknown as typeof fetch,
    });
    expect(result).toMatchObject({ reason: "redirected" });
  });

  it("reports a connection failure", async () => {
    const result = await fetchGuardedJson("https://app.example.org/jwks", {
      resolve: publicResolve,
      fetchImpl: (() =>
        Promise.reject(new Error("ECONNREFUSED"))) as unknown as typeof fetch,
    });
    expect(result).toMatchObject({ reason: "unreachable" });
  });

  it("refuses a non-2xx response", async () => {
    const result = await fetchGuardedJson("https://app.example.org/jwks", {
      resolve: publicResolve,
      fetchImpl: jsonFetch({}, 404),
    });
    expect(result).toMatchObject({ reason: "bad-status" });
  });

  it("refuses a body that is not JSON", async () => {
    const result = await fetchGuardedJson("https://app.example.org/jwks", {
      resolve: publicResolve,
      fetchImpl: (() =>
        Promise.resolve(new Response("<html>"))) as unknown as typeof fetch,
    });
    expect(result).toMatchObject({ reason: "not-json" });
  });

  it("refuses an oversized body without buffering all of it", async () => {
    const result = await fetchGuardedJson("https://app.example.org/jwks", {
      resolve: publicResolve,
      maxBytes: 16,
      fetchImpl: jsonFetch({ padding: "x".repeat(64) }),
    });
    expect(result).toMatchObject({ reason: "too-large" });
  });

  it("accepts a body at the default limit", async () => {
    expect(DEFAULT_OUTBOUND_MAX_BYTES).toBeGreaterThan(1024);
    const result = await fetchGuardedJson("https://app.example.org/jwks", {
      resolve: publicResolve,
      fetchImpl: jsonFetch({ padding: "x".repeat(1024) }),
    });
    expect(result.ok).toBe(true);
  });

  it("treats an empty body as invalid JSON rather than throwing", async () => {
    const result = await fetchGuardedJson("https://app.example.org/jwks", {
      resolve: publicResolve,
      fetchImpl: (() =>
        Promise.resolve(
          new Response(null, { status: 204 }),
        )) as unknown as typeof fetch,
    });
    expect(result).toMatchObject({ reason: "not-json" });
  });
});
