/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  parseScopePattern,
  scopeMatchesIntersects,
  scopeMatchesWithin,
} from "./pattern.js";
import { parseScope } from "../scopes/index.js";

import type { ParsedScopePattern } from "./types.js";
import type { Scope } from "../scopes/types.js";

/** Parses a scope, failing the test if it was rejected. */
function scope(raw: string): Scope {
  const result = parseScope(raw);
  if (!result.ok) {
    throw new Error(`Expected "${raw}" to parse, got ${result.code}`);
  }
  return result.scope;
}

/** Parses a pattern, failing the test if it was rejected. */
function pattern(raw: string): ParsedScopePattern {
  const parsed = parseScopePattern(raw);
  if (parsed === undefined) {
    throw new Error(`Expected "${raw}" to parse as a pattern`);
  }
  return parsed;
}

/** Convenience wrapper for within matching of two strings. */
function within(patternText: string, scopeText: string): boolean {
  return scopeMatchesWithin(scope(scopeText), pattern(patternText));
}

/** Convenience wrapper for intersects matching of two strings. */
function intersects(patternText: string, scopeText: string): boolean {
  return scopeMatchesIntersects(scope(scopeText), pattern(patternText));
}

describe("parseScopePattern", () => {
  it("parses a fully specified pattern", () => {
    expect(parseScopePattern("patient/Observation.rs")).toEqual({
      context: "patient",
      resourceType: "Observation",
      permissions: ["r", "s"],
    });
  });

  it("parses a wildcard context", () => {
    expect(parseScopePattern("*/Observation.r")).toEqual({
      context: "*",
      resourceType: "Observation",
      permissions: ["r"],
    });
  });

  it("parses a wildcard resource type", () => {
    expect(parseScopePattern("system/*.cruds")).toEqual({
      context: "system",
      resourceType: "*",
      permissions: ["c", "r", "u", "d", "s"],
    });
  });

  it("parses a doubly wildcarded pattern", () => {
    expect(parseScopePattern("*/*.r")).toEqual({
      context: "*",
      resourceType: "*",
      permissions: ["r"],
    });
  });

  it("accepts every scope context", () => {
    for (const context of ["patient", "user", "system"] as const) {
      expect(parseScopePattern(`${context}/*.r`)?.context).toBe(context);
    }
  });

  it("expands v1 permission suffixes, matching the scope parser", () => {
    expect(parseScopePattern("patient/*.read")?.permissions).toEqual([
      "r",
      "s",
    ]);
    expect(parseScopePattern("patient/*.write")?.permissions).toEqual([
      "c",
      "u",
      "d",
    ]);
    expect(parseScopePattern("patient/*.*")?.permissions).toEqual([
      "c",
      "r",
      "u",
      "d",
      "s",
    ]);
  });

  it.each([
    ["", "empty"],
    ["openid", "an identity scope"],
    ["fhirUser", "an identity scope"],
    ["offline_access", "a refresh scope"],
    ["launch/patient", "a launch scope"],
    ["launch", "the bare launch scope"],
    ["__custom.manage", "a custom scope"],
    ["https://example.org/foo", "a URI scope"],
    ["patient/Observation", "no permission suffix"],
    ["patient/Observation.", "an empty permission suffix"],
    ["patient/Observation.x", "an unknown permission letter"],
    ["patient/Observation.sr", "out-of-order permissions"],
    ["patient/Observation.rr", "a duplicated permission"],
    ["admin/Observation.r", "an unknown context"],
    ["patient/observation.r", "a lower case resource type"],
    ["patient/Obs-ervation.r", "a punctuated resource type"],
    ["patient//Observation.r", "an empty resource type"],
    ["/Observation.r", "an empty context"],
    ["Observation.r", "no context"],
    ["patient/*.rs?category=laboratory", "a search parameter restriction"],
    ["*/*.r?a=b", "a wildcard with a restriction"],
  ])("rejects %j because it has %s", (input) => {
    expect(parseScopePattern(input)).toBeUndefined();
  });
});

describe("scopeMatchesWithin", () => {
  it("matches an identical scope", () => {
    expect(within("patient/Observation.rs", "patient/Observation.rs")).toBe(
      true,
    );
  });

  it("matches a scope asking for fewer permissions", () => {
    expect(within("patient/*.rs", "patient/Observation.r")).toBe(true);
    expect(within("patient/*.cruds", "patient/Observation.cud")).toBe(true);
  });

  it("refuses a scope asking for more permissions", () => {
    expect(within("patient/*.rs", "patient/Observation.cud")).toBe(false);
    expect(within("patient/*.rs", "patient/Observation.rus")).toBe(false);
    expect(within("patient/*.r", "patient/Observation.rs")).toBe(false);
  });

  it("requires the same context unless the pattern wildcards it", () => {
    expect(within("patient/*.r", "user/Observation.r")).toBe(false);
    expect(within("user/*.r", "patient/Observation.r")).toBe(false);
    expect(within("system/*.r", "user/Observation.r")).toBe(false);
    expect(within("*/*.r", "user/Observation.r")).toBe(true);
    expect(within("*/*.r", "system/Observation.r")).toBe(true);
  });

  it("requires the same resource type unless the pattern wildcards it", () => {
    expect(within("patient/Observation.r", "patient/Condition.r")).toBe(false);
    expect(within("patient/Observation.r", "patient/Observation.r")).toBe(true);
    expect(within("patient/*.r", "patient/Condition.r")).toBe(true);
  });

  it("does not let a wildcard scope slip inside a concrete pattern", () => {
    // The security-relevant asymmetry: `patient/*.r` asks for every type, which
    // is strictly more than `patient/Observation.r` permits.
    expect(within("patient/Observation.r", "patient/*.r")).toBe(false);
  });

  it("matches a wildcard scope against a wildcard pattern", () => {
    expect(within("patient/*.r", "patient/*.r")).toBe(true);
    expect(within("*/*.rs", "system/*.rs")).toBe(true);
  });

  it("ignores search parameter restrictions on the scope", () => {
    expect(within("patient/*.rs", "patient/Observation.rs?category=lab")).toBe(
      true,
    );
  });

  it.each([
    "openid",
    "fhirUser",
    "profile",
    "offline_access",
    "online_access",
    "launch",
    "launch/patient",
    "launch/encounter",
    "__experimental.manage",
    "https://example.org/scope",
  ])("never matches the non-resource scope %s", (raw) => {
    expect(within("*/*.cruds", raw)).toBe(false);
    expect(intersects("*/*.cruds", raw)).toBe(false);
  });
});

describe("scopeMatchesIntersects", () => {
  it("matches when a single permission is shared", () => {
    expect(intersects("*/*.r", "patient/Observation.rs")).toBe(true);
    expect(intersects("*/*.s", "patient/Observation.rs")).toBe(true);
    expect(intersects("*/*.cud", "patient/Observation.cs")).toBe(true);
  });

  it("does not require the scope to be a subset", () => {
    expect(intersects("*/*.r", "patient/Observation.cruds")).toBe(true);
    expect(within("*/*.r", "patient/Observation.cruds")).toBe(false);
  });

  it("refuses when no permission is shared", () => {
    expect(intersects("*/*.cud", "patient/Observation.rs")).toBe(false);
    expect(intersects("*/*.r", "patient/Observation.s")).toBe(false);
    expect(intersects("*/*.d", "patient/Observation.cu")).toBe(false);
  });

  it("still honours the context and resource type", () => {
    expect(intersects("system/*.r", "patient/Observation.rs")).toBe(false);
    expect(intersects("system/*.r", "system/Observation.rs")).toBe(true);
    expect(intersects("*/Observation.r", "patient/Condition.rs")).toBe(false);
    expect(intersects("*/Observation.r", "patient/Observation.rs")).toBe(true);
  });

  it("does not match a wildcard scope against a concrete pattern type", () => {
    expect(intersects("*/Observation.r", "system/*.r")).toBe(false);
  });
});
