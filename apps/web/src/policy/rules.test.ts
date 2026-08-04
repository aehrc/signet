/**
 * Author: John Grimes
 */

import { describe, expect, it } from "vitest";

import {
  appendRule,
  generateRuleId,
  isRuleEnabled,
  moveRule,
  removeRule,
  replaceRule,
  rulesIn,
  setRuleEnabled,
  usedRuleIds,
  withRuleIds,
} from "./rules.js";

import type { PolicyDocument } from "@signet/core";

/** A document with three grants, so ordering is observable. */
function documentWithGrants(): PolicyDocument {
  return {
    version: 1,
    scopeGrants: [
      { id: "a", match: "patient/*.rs", allow: true },
      { id: "b", match: "user/*.rs", allow: true },
      { id: "c", match: "system/*.rs", allow: true },
    ],
    claimRules: [],
    contextRules: [],
    defaults: { accessTokenTtl: 300, refreshTokenTtl: 3600 },
  };
}

/** The identifiers of a document's grants, in order. */
function grantIds(document: PolicyDocument): string[] {
  return document.scopeGrants.map((rule) => rule.id ?? "");
}

describe("generateRuleId", () => {
  it("prefixes with the singular list name", () => {
    expect(generateRuleId("scopeGrants", new Set())).toMatch(/^scopeGrant-/);
    expect(generateRuleId("claimRules", new Set())).toMatch(/^claimRule-/);
  });

  it("does not collide with an identifier already in use", () => {
    const taken = new Set(["scopeGrant-abc"]);
    for (let attempt = 0; attempt < 20; attempt += 1) {
      expect(taken.has(generateRuleId("scopeGrants", taken))).toBe(false);
    }
  });
});

describe("usedRuleIds", () => {
  it("collects identifiers from every list", () => {
    const document: PolicyDocument = {
      ...documentWithGrants(),
      claimRules: [{ id: "claim", when: { always: true }, emit: { a: "b" } }],
      scopeMappings: [
        {
          id: "map",
          forEachScope: "*/*.r",
          appendTo: "authorities",
          values: ["x"],
        },
      ],
      contextRules: [{ id: "ctx", emit: { patient: "p" } }],
    };
    expect(usedRuleIds(document)).toEqual(
      new Set(["a", "b", "c", "claim", "map", "ctx"]),
    );
  });
});

describe("withRuleIds", () => {
  it("gives an unidentified rule an identifier", () => {
    const document: PolicyDocument = {
      ...documentWithGrants(),
      scopeGrants: [{ match: "patient/*.rs", allow: true }],
    };
    const identified = withRuleIds(document);
    expect(identified.scopeGrants[0]?.id).toBeDefined();
  });

  it("leaves existing identifiers alone", () => {
    const document = documentWithGrants();
    expect(grantIds(withRuleIds(document))).toEqual(["a", "b", "c"]);
  });

  it("does not reuse an identifier from another list", () => {
    const document: PolicyDocument = {
      ...documentWithGrants(),
      scopeGrants: [{ match: "patient/*.rs", allow: true }],
      claimRules: [{ when: { always: true }, emit: { a: "b" } }],
    };
    const identified = withRuleIds(document);
    const ids = [identified.scopeGrants[0]?.id, identified.claimRules[0]?.id];
    expect(new Set(ids).size).toBe(2);
  });
});

describe("moveRule", () => {
  it("moves a rule earlier", () => {
    expect(
      grantIds(moveRule(documentWithGrants(), "scopeGrants", "b", -1)),
    ).toEqual(["b", "a", "c"]);
  });

  it("moves a rule later", () => {
    expect(
      grantIds(moveRule(documentWithGrants(), "scopeGrants", "b", 1)),
    ).toEqual(["a", "c", "b"]);
  });

  it("does nothing at the start", () => {
    expect(
      grantIds(moveRule(documentWithGrants(), "scopeGrants", "a", -1)),
    ).toEqual(["a", "b", "c"]);
  });

  it("does nothing at the end", () => {
    expect(
      grantIds(moveRule(documentWithGrants(), "scopeGrants", "c", 1)),
    ).toEqual(["a", "b", "c"]);
  });

  it("does nothing for a rule that is not there", () => {
    expect(
      grantIds(moveRule(documentWithGrants(), "scopeGrants", "nope", 1)),
    ).toEqual(["a", "b", "c"]);
  });
});

describe("replaceRule and removeRule", () => {
  it("replaces in place, preserving order", () => {
    const edited = replaceRule(documentWithGrants(), "scopeGrants", "b", {
      id: "b",
      match: "user/*.cud",
      allow: false,
    });
    expect(grantIds(edited)).toEqual(["a", "b", "c"]);
    expect(edited.scopeGrants[1]?.match).toBe("user/*.cud");
  });

  it("removes one rule", () => {
    expect(
      grantIds(removeRule(documentWithGrants(), "scopeGrants", "b")),
    ).toEqual(["a", "c"]);
  });
});

describe("setRuleEnabled", () => {
  it("disables by writing the flag", () => {
    const disabled = setRuleEnabled(
      documentWithGrants(),
      "scopeGrants",
      "a",
      false,
    );
    const rule = disabled.scopeGrants[0];
    expect(rule?.enabled).toBe(false);
    expect(rule === undefined ? undefined : isRuleEnabled(rule)).toBe(false);
  });

  it("enables by removing the flag rather than setting it to true", () => {
    // Enabled is the default, and `enabled: true` in the code view is noise the
    // reader has to decide to ignore.
    const disabled = setRuleEnabled(
      documentWithGrants(),
      "scopeGrants",
      "a",
      false,
    );
    const enabled = setRuleEnabled(disabled, "scopeGrants", "a", true);
    expect(Object.keys(enabled.scopeGrants[0] ?? {})).not.toContain("enabled");
  });
});

describe("appendRule", () => {
  it("appends at the end, since order decides precedence", () => {
    const appended = appendRule(documentWithGrants(), "scopeGrants", {
      match: "patient/*.cud",
      allow: false,
    });
    expect(appended.scopeGrants).toHaveLength(4);
    expect(appended.scopeGrants.at(-1)?.match).toBe("patient/*.cud");
    expect(appended.scopeGrants.at(-1)?.id).toBeDefined();
  });

  it("creates the scope mapping list when there is none", () => {
    const appended = appendRule(documentWithGrants(), "scopeMappings", {
      forEachScope: "*/*.r",
      appendTo: "authorities",
      values: ["pathling:read"],
    });
    expect(appended.scopeMappings).toHaveLength(1);
  });

  it("drops the scope mapping list when its last rule goes", () => {
    // The field is optional; an empty array in the code view is a question the
    // reader should not have to answer.
    const appended = appendRule(documentWithGrants(), "scopeMappings", {
      id: "only",
      forEachScope: "*/*.r",
      appendTo: "authorities",
      values: ["x"],
    });
    const emptied = removeRule(appended, "scopeMappings", "only");
    expect(Object.keys(emptied)).not.toContain("scopeMappings");
    expect(rulesIn(emptied, "scopeMappings")).toEqual([]);
  });
});
