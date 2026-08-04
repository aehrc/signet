/**
 * Author: John Grimes
 */

import { describe, expect, it } from "vitest";

import { formatPolicy, parsePolicy, policiesDiffer } from "./document.js";

import type { PolicyDocument } from "@signet/core";

const document: PolicyDocument = {
  version: 1,
  scopeGrants: [
    { id: "grant-read", match: "patient/*.rs", allow: true, narrow: true },
  ],
  claimRules: [
    {
      id: "claim-user",
      when: { hasUser: true },
      emit: { fhirUser: "{{ user.fhirUser }}" },
    },
  ],
  contextRules: [
    { id: "context-patient", emit: { patient: "{{ context.patient }}" } },
  ],
  defaults: { accessTokenTtl: 300, refreshTokenTtl: 3600 },
};

describe("formatPolicy and parsePolicy", () => {
  it("round-trips a document unchanged", () => {
    const parsed = parsePolicy(formatPolicy(document));
    expect(parsed).toEqual({ ok: true, document });
  });

  it("is stable, so a diff between two renderings means something", () => {
    expect(formatPolicy(document)).toBe(formatPolicy(document));
  });

  it("reports a syntax error against the document as a whole", () => {
    const parsed = parsePolicy("{ not json");
    expect(parsed.ok).toBe(false);
    const issues = parsed.ok ? [] : parsed.issues;
    expect(issues[0]?.path).toBe("");
    expect(issues[0]?.message.length).toBeGreaterThan(0);
  });

  it("reports a validation failure at the path the validator gave it", () => {
    const broken = {
      ...document,
      claimRules: [{ when: { always: true }, emit: { a: "{{ user.fhirUser" } }],
    };
    const parsed = parsePolicy(JSON.stringify(broken));

    expect(parsed.ok).toBe(false);
    const issues = parsed.ok ? [] : parsed.issues;
    expect(issues[0]?.path).toBe("claimRules.0.emit.a");
  });

  it("refuses a document that is valid JSON but not a policy", () => {
    expect(parsePolicy('{"hello":"world"}').ok).toBe(false);
    expect(parsePolicy("[]").ok).toBe(false);
    expect(parsePolicy('"a string"').ok).toBe(false);
  });

  it("refuses an unknown scope pattern, as the server would", () => {
    // The editor and the API share one validator, so this fails here for the same
    // reason and at the same path as it would on save.
    const parsed = parsePolicy(
      JSON.stringify({
        ...document,
        scopeGrants: [{ match: "nonsense", allow: true }],
      }),
    );
    expect(parsed.ok).toBe(false);
  });
});

describe("policiesDiffer", () => {
  it("is false for the same document", () => {
    expect(policiesDiffer(document, { ...document })).toBe(false);
  });

  it("is true when a rule changes", () => {
    expect(
      policiesDiffer(document, {
        ...document,
        defaults: { accessTokenTtl: 600, refreshTokenTtl: 3600 },
      }),
    ).toBe(true);
  });

  it("notices a reordering", () => {
    // Order is significant in every rule list, so a reorder is a change.
    const reordered: PolicyDocument = {
      ...document,
      scopeGrants: [
        { id: "grant-write", match: "patient/*.cud", allow: false },
        ...document.scopeGrants,
      ],
    };
    expect(policiesDiffer(document, reordered)).toBe(true);
  });
});
