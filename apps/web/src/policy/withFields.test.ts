import { describe, expect, it } from "vitest";

import { withFields } from "./rules.js";

import type { ScopeGrantRule } from "@signet/core";

const rule: ScopeGrantRule = {
  id: "grant-read",
  match: "patient/*.rs",
  allow: true,
  narrow: true,
  requireContext: ["patient"],
};

describe("withFields", () => {
  it("sets a field", () => {
    expect(withFields(rule, { match: "user/*.rs" })).toMatchObject({
      match: "user/*.rs",
      allow: true,
    });
  });

  it("removes a field rather than setting it to undefined", () => {
    // The document's optional fields mean absent, not present-and-empty: a grant rule
    // with no `requireContext` places no requirement, and one holding `undefined`
    // would be a key the code view shows and the validator questions.
    const next = withFields(rule, { requireContext: undefined });
    expect(Object.keys(next)).not.toContain("requireContext");
  });

  it("leaves the fields it was not asked about alone", () => {
    expect(withFields(rule, { narrow: false })).toMatchObject({
      id: "grant-read",
      match: "patient/*.rs",
      requireContext: ["patient"],
      narrow: false,
    });
  });

  it("distinguishes an empty list from an absent one", () => {
    // `grantTypes: []` applies to no grant type at all; absent applies to every one.
    // A control that emptied a list must be able to express either.
    const empty = withFields(rule, { grantTypes: [] });
    expect(empty).toMatchObject({ grantTypes: [] });

    const absent = withFields(empty, { grantTypes: undefined });
    expect(Object.keys(absent)).not.toContain("grantTypes");
  });

  it("does not mutate the rule it was given", () => {
    const before = JSON.stringify(rule);
    withFields(rule, { match: "user/*.rs", requireContext: undefined });
    expect(JSON.stringify(rule)).toBe(before);
  });
});
