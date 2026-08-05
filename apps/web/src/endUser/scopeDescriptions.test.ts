/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  describeScope,
  describeScopes,
  includesWrites,
} from "./scopeDescriptions.js";

describe("describeScope", () => {
  it("describes a patient-context read", () => {
    expect(describeScope("patient/Observation.rs")).toEqual({
      scope: "patient/Observation.rs",
      description: "Read your test results and measurements",
      writes: false,
    });
  });

  it("marks a scope that permits changing data", () => {
    const described = describeScope("patient/Condition.cu");
    expect(described.writes).toBe(true);
    expect(described.description).toBe(
      "Add to or change your health conditions",
    );
  });

  it("marks a scope that permits deletion", () => {
    expect(describeScope("patient/Observation.d").writes).toBe(true);
    expect(describeScope("patient/Observation.d").description).toBe(
      "Delete your test results and measurements",
    );
  });

  it("lists several actions in English", () => {
    expect(describeScope("patient/Observation.cruds").description).toBe(
      "Read, add to or change and delete your test results and measurements",
    );
  });

  it("does not say `your` for a user-context scope", () => {
    // A user-context scope covers everything the person may see, not only their own
    // record, and "your test results" would understate it.
    const described = describeScope("user/Observation.rs");
    expect(described.description).toBe(
      "Read test results and measurements that you have access to",
    );
  });

  it("says so when a scope covers the whole server", () => {
    expect(describeScope("system/Observation.rs").description).toContain(
      "across the whole server",
    );
  });

  it("describes the wildcard as everything", () => {
    expect(describeScope("patient/*.rs").description).toBe(
      "Read all of your health information",
    );
  });

  it("describes the named scopes", () => {
    expect(describeScope("openid").description).toBe("Confirm who you are");
    expect(describeScope("offline_access").description).toContain(
      "when you are not using the app",
    );
    expect(describeScope("launch/patient").description).toContain(
      "which patient",
    );
  });

  it("falls back to the resource type it does not have a phrase for", () => {
    // Better than a wrong phrase, and much better than omitting the line.
    expect(describeScope("patient/NutritionOrder.rs").description).toBe(
      "Read your NutritionOrder records",
    );
  });

  it("does not drop a scope it cannot parse", () => {
    const described = describeScope("something-odd");
    expect(described.description).toContain("something-odd");
    expect(described.writes).toBe(false);
  });

  it("normalises a v1 scope, as the grammar does", () => {
    expect(describeScope("patient/Observation.read").description).toBe(
      "Read your test results and measurements",
    );
  });
});

describe("describeScopes", () => {
  it("keeps the order the app asked in", () => {
    const scopes = ["openid", "patient/Observation.rs", "offline_access"];
    expect(describeScopes(scopes).map((entry) => entry.scope)).toEqual(scopes);
  });
});

describe("includesWrites", () => {
  it("is true when any scope permits writing", () => {
    expect(
      includesWrites(["patient/Observation.rs", "patient/Condition.cud"]),
    ).toBe(true);
  });

  it("is false for a read-only request", () => {
    expect(includesWrites(["openid", "patient/Observation.rs"])).toBe(false);
  });
});
