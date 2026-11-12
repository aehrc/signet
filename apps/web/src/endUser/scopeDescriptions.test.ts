/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

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
    expect(describeScope("patient/Observation.rs", "smart")).toEqual({
      scope: "patient/Observation.rs",
      description: "Read your test results and measurements",
      writes: false,
    });
  });

  it("marks a scope that permits changing data", () => {
    const described = describeScope("patient/Condition.cu", "smart");
    expect(described.writes).toBe(true);
    expect(described.description).toBe(
      "Add to or change your health conditions",
    );
  });

  it("marks a scope that permits deletion", () => {
    expect(describeScope("patient/Observation.d", "smart").writes).toBe(true);
    expect(describeScope("patient/Observation.d", "smart").description).toBe(
      "Delete your test results and measurements",
    );
  });

  it("lists several actions in English", () => {
    expect(
      describeScope("patient/Observation.cruds", "smart").description,
    ).toBe(
      "Read, add to or change and delete your test results and measurements",
    );
  });

  it("does not say `your` for a user-context scope", () => {
    // A user-context scope covers everything the person may see, not only their own
    // record, and "your test results" would understate it.
    const described = describeScope("user/Observation.rs", "smart");
    expect(described.description).toBe(
      "Read test results and measurements that you have access to",
    );
  });

  it("says so when a scope covers the whole server", () => {
    expect(
      describeScope("system/Observation.rs", "smart").description,
    ).toContain("across the whole server");
  });

  it("describes the wildcard as everything", () => {
    expect(describeScope("patient/*.rs", "smart").description).toBe(
      "Read all of your health information",
    );
  });

  it("describes the named scopes", () => {
    expect(describeScope("openid", "smart").description).toBe(
      "Confirm who you are",
    );
    expect(describeScope("offline_access", "smart").description).toContain(
      "when you are not using the app",
    );
    expect(describeScope("launch/patient", "smart").description).toContain(
      "which patient",
    );
  });

  it("falls back to the resource type it does not have a phrase for", () => {
    // Better than a wrong phrase, and much better than omitting the line.
    expect(
      describeScope("patient/NutritionOrder.rs", "smart").description,
    ).toBe("Read your NutritionOrder records");
  });

  it("does not drop a scope it cannot parse", () => {
    const described = describeScope("something-odd", "smart");
    expect(described.description).toContain("something-odd");
    expect(described.writes).toBe(false);
  });

  it("normalises a v1 scope, as the grammar does", () => {
    expect(describeScope("patient/Observation.read", "smart").description).toBe(
      "Read your test results and measurements",
    );
  });
});

describe("describeScopes", () => {
  it("keeps the order the app asked in", () => {
    const scopes = ["openid", "patient/Observation.rs", "offline_access"];
    expect(describeScopes(scopes, "smart").map((entry) => entry.scope)).toEqual(
      scopes,
    );
  });
});

describe("includesWrites", () => {
  it("is true when any scope permits writing", () => {
    expect(
      includesWrites(
        ["patient/Observation.rs", "patient/Condition.cud"],
        "smart",
      ),
    ).toBe(true);
  });

  it("is false for a read-only request", () => {
    expect(includesWrites(["openid", "patient/Observation.rs"], "smart")).toBe(
      false,
    );
  });
});

describe("describeScope on an OAuth endpoint", () => {
  it("describes the OpenID Connect scopes in plain English", () => {
    expect(describeScope("openid", "oauth").description).toBe(
      "Confirm who you are",
    );
    expect(describeScope("profile", "oauth").description).toBe(
      "Know your name and username",
    );
    expect(describeScope("email", "oauth").description).toBe(
      "Know your email address",
    );
    expect(describeScope("offline_access", "oauth").description).toBe(
      "Keep this access when you are not using the app",
    );
  });

  it("shows the granting rule's description for an API scope", () => {
    expect(
      describeScope("orders:read", "oauth", {
        "orders:read": "Read your orders",
      }),
    ).toEqual({
      scope: "orders:read",
      description: "Read your orders",
      writes: false,
    });
  });

  it("falls back to the scope itself when the rule has no description", () => {
    expect(describeScope("orders:read", "oauth").description).toBe(
      "orders:read",
    );
  });

  it("reads a SMART-shaped string as an opaque scope", () => {
    // On an OAuth endpoint `patient/Observation.rs` is only a string, so phrasing
    // it as access to health records would describe something it does not grant.
    expect(describeScope("patient/Observation.rs", "oauth").description).toBe(
      "patient/Observation.rs",
    );
    expect(describeScope("fhirUser", "oauth").description).toBe("fhirUser");
  });

  it("prefers the operator's description over its own wording", () => {
    // Only for an API scope: the identity scopes mean the same everywhere.
    expect(
      describeScope("email", "oauth", { email: "Something else" }).description,
    ).toBe("Know your email address");
  });
});

describe("describeScopes on an OAuth endpoint", () => {
  it("describes each scope with the descriptions it was given", () => {
    expect(
      describeScopes(["openid", "orders:read"], "oauth", {
        "orders:read": "Read your orders",
      }).map((entry) => entry.description),
    ).toEqual(["Confirm who you are", "Read your orders"]);
  });
});

describe("includesWrites on an OAuth endpoint", () => {
  it("is false, because an opaque scope says nothing about writing", () => {
    expect(includesWrites(["patient/Observation.cud"], "oauth")).toBe(false);
  });
});
