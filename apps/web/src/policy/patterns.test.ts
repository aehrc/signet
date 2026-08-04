/**
 * Author: John Grimes
 */

import { describe, expect, it } from "vitest";

import {
  DEFAULT_PATTERN,
  formatPattern,
  patternDraft,
  withPermission,
} from "./patterns.js";

describe("patternDraft", () => {
  it("reads a resource pattern into the controls", () => {
    expect(patternDraft("patient/Observation.rs")).toEqual({
      context: "patient",
      resourceType: "Observation",
      permissions: ["r", "s"],
    });
  });

  it("reads a wildcard context", () => {
    expect(patternDraft("*/*.cruds")).toEqual({
      context: "*",
      resourceType: "*",
      permissions: ["c", "r", "u", "d", "s"],
    });
  });

  it("normalises a v1 suffix, as the grammar does", () => {
    expect(patternDraft("patient/*.read")?.permissions).toEqual(["r", "s"]);
  });

  it("returns undefined for a scope matched by equality rather than pattern", () => {
    // `openid` and `launch/patient` are not resource patterns; a rule matching one
    // is shown as a plain value instead of pickers.
    expect(patternDraft("openid")).toBeUndefined();
    expect(patternDraft("launch/patient")).toBeUndefined();
  });

  it("returns undefined for a pattern carrying search parameters", () => {
    // The pickers have nowhere to put them, and dropping them would widen the rule.
    expect(patternDraft("patient/Observation.rs?category=x")).toBeUndefined();
  });
});

describe("formatPattern", () => {
  it("round-trips a pattern", () => {
    for (const pattern of [
      "patient/Observation.rs",
      "user/*.cruds",
      "system/Condition.cud",
      "*/*.r",
    ]) {
      const draft = patternDraft(pattern);
      expect(draft).toBeDefined();
      expect(draft === undefined ? "" : formatPattern(draft)).toBe(pattern);
    }
  });

  it("orders the permissions by the grammar, not by click order", () => {
    // `.sr` is not a valid suffix; the letters must read in `cruds` order.
    expect(
      formatPattern({
        context: "patient",
        resourceType: "*",
        permissions: ["s", "r"],
      }),
    ).toBe("patient/*.rs");
  });

  it("falls back to read rather than emitting a rule that matches nothing", () => {
    expect(
      formatPattern({ context: "user", resourceType: "*", permissions: [] }),
    ).toBe("user/*.r");
  });

  it("treats a blank resource type as the wildcard", () => {
    expect(
      formatPattern({
        context: "user",
        resourceType: "  ",
        permissions: ["r"],
      }),
    ).toBe("user/*.r");
  });

  it("trims a pasted resource type", () => {
    expect(
      formatPattern({
        context: "user",
        resourceType: " Observation ",
        permissions: ["r"],
      }),
    ).toBe("user/Observation.r");
  });
});

describe("withPermission", () => {
  it("adds a permission in grammar order", () => {
    expect(withPermission(DEFAULT_PATTERN, "c", true).permissions).toEqual([
      "c",
      "r",
      "s",
    ]);
  });

  it("removes a permission", () => {
    expect(withPermission(DEFAULT_PATTERN, "s", false).permissions).toEqual([
      "r",
    ]);
  });

  it("does not duplicate one that is already selected", () => {
    expect(withPermission(DEFAULT_PATTERN, "r", true).permissions).toEqual([
      "r",
      "s",
    ]);
  });
});
