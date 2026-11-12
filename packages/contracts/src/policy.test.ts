/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { policyDocumentSchemaFor, policyIssuePath } from "./policy.js";

const policyDocumentSchema = policyDocumentSchemaFor("smart");

describe("policyIssuePath", () => {
  it("treats the empty path as the document itself", () => {
    expect(policyIssuePath("")).toEqual([]);
  });

  it("splits property accessors", () => {
    expect(policyIssuePath("defaults.accessTokenTtl")).toEqual([
      "defaults",
      "accessTokenTtl",
    ]);
  });

  it("reads an array index as a number", () => {
    expect(policyIssuePath("claimRules[2].emit.patient_id")).toEqual([
      "claimRules",
      2,
      "emit",
      "patient_id",
    ]);
  });

  it("reads consecutive indices", () => {
    expect(policyIssuePath("scopeMappings[0].values[1]")).toEqual([
      "scopeMappings",
      0,
      "values",
      1,
    ]);
  });

  it("keeps a segment that is not an index rather than dropping it", () => {
    expect(policyIssuePath("emit[weird]")).toEqual(["emit", "weird"]);
  });
});

describe("policyDocumentSchemaFor", () => {
  const valid = {
    version: 1,
    scopeGrants: [{ match: "patient/*.rs", allow: true }],
    claimRules: [
      { when: { always: true }, emit: { a: "{{ user.fhirUser }}" } },
    ],
    contextRules: [],
    defaults: { accessTokenTtl: 300, refreshTokenTtl: 3600 },
  };

  it("parses a valid document", () => {
    const result = policyDocumentSchema.safeParse(valid);
    expect(result.success).toBe(true);
    expect(result.data?.scopeGrants[0]?.match).toBe("patient/*.rs");
  });

  it("reports a core validation issue at the path core gave it", () => {
    const result = policyDocumentSchema.safeParse({
      ...valid,
      claimRules: [{ when: { always: true }, emit: { a: "{{ user.fhirUser" } }],
    });

    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.path).toEqual([
      "claimRules",
      0,
      "emit",
      "a",
    ]);
  });

  it("refuses a document that is not an object", () => {
    expect(policyDocumentSchema.safeParse("nope").success).toBe(false);
  });

  it("validates under the scope grammar of the endpoint's kind", () => {
    const oauth = {
      ...valid,
      scopeGrants: [{ match: "orders:read", allow: true }],
    };
    expect(policyDocumentSchemaFor("oauth").safeParse(oauth).success).toBe(
      true,
    );
    expect(policyDocumentSchema.safeParse(oauth).success).toBe(false);
  });
});
