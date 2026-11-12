/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The scope grammar of an OAuth / OpenID Connect endpoint.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { parseScope, parseScopes } from "./parse.js";
import { formatScope } from "./serialise.js";

import type { Scope } from "./types.js";

/** Parses a scope on an OAuth endpoint, failing the test if it was rejected. */
function oauth(raw: string): Scope {
  const result = parseScope(raw, "oauth");
  if (!result.ok) {
    throw new Error(`Expected "${raw}" to parse, got ${result.code}`);
  }
  return result.scope;
}

describe("parseScope - OAuth endpoint grammar", () => {
  it("reads the OpenID Connect scopes as identity scopes", () => {
    expect(oauth("openid")).toEqual({ kind: "identity", name: "openid" });
    expect(oauth("profile")).toEqual({ kind: "identity", name: "profile" });
    expect(oauth("email")).toEqual({ kind: "identity", name: "email" });
  });

  it("reads offline_access as a refresh scope", () => {
    expect(oauth("offline_access")).toEqual({
      kind: "refresh",
      name: "offline_access",
    });
  });

  it("reads any other scope-token as an opaque custom scope", () => {
    for (const raw of [
      "orders:read",
      "read",
      "api.write",
      "https://api.example.org/orders",
    ]) {
      expect(oauth(raw)).toEqual({ kind: "custom", value: raw });
    }
  });

  it("gives SMART-shaped strings no SMART meaning", () => {
    for (const raw of [
      "patient/Observation.rs",
      "launch",
      "launch/patient",
      "fhirUser",
      "online_access",
      "system/*.cruds",
    ]) {
      expect(oauth(raw)).toEqual({ kind: "custom", value: raw });
    }
  });

  it("round-trips an opaque scope unchanged", () => {
    expect(formatScope(oauth("patient/Observation.read"))).toBe(
      "patient/Observation.read",
    );
  });

  it("refuses characters RFC 6749 does not allow in a scope-token", () => {
    for (const raw of [
      'say"hi',
      String.raw`back\slash`,
      "tab\there",
      "naïve",
    ]) {
      const result = parseScope(raw, "oauth");
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("malformed");
      }
    }
  });

  it("refuses an empty scope", () => {
    const result = parseScope("", "oauth");
    expect(result.ok).toBe(false);
  });
});

describe("parseScope - email on a SMART endpoint", () => {
  it("stays unrecognised, because SMART does not define it", () => {
    expect(parseScope("email", "smart").ok).toBe(false);
  });

  it("keeps the opaque OAuth scopes refused", () => {
    expect(parseScope("orders:read", "smart").ok).toBe(false);
  });
});

describe("parseScopes - OAuth endpoint grammar", () => {
  it("parses a whole scope parameter", () => {
    const parsed = parseScopes("openid email orders:read", "oauth");
    expect(parsed.rejected).toEqual([]);
    expect(parsed.scopes.map((scope) => formatScope(scope))).toEqual([
      "openid",
      "email",
      "orders:read",
    ]);
  });
});
