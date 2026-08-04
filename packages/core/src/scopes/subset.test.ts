/**
 * Author: John Grimes
 */

import { describe, expect, it } from "vitest";

import { parseScope, parseScopes } from "./parse.js";
import { formatScope } from "./serialise.js";
import {
  areScopesCoveredBy,
  isScopeCoveredBy,
  isScopeSubsetOf,
  narrowToPermitted,
} from "./subset.js";

import type { Scope } from "./types.js";

/** Parses a scope, failing the test if it was rejected. */
function scope(raw: string): Scope {
  const result = parseScope(raw);
  if (!result.ok) {
    throw new Error(`Expected "${raw}" to parse, got ${result.code}`);
  }
  return result.scope;
}

/** Parses a set of scopes from a space-delimited string. */
function scopes(raw: string): readonly Scope[] {
  const result = parseScopes(raw);
  if (result.rejected.length > 0) {
    throw new Error(
      `Unexpected rejections: ${result.rejected.map((r) => r.raw).join(", ")}`,
    );
  }
  return result.scopes;
}

/** Asserts the subset relation between two scope strings. */
function covers(permitted: string, candidate: string): boolean {
  return isScopeSubsetOf(scope(candidate), scope(permitted));
}

describe("isScopeSubsetOf - permissions", () => {
  it("treats an identical scope as a subset of itself", () => {
    expect(covers("patient/Observation.rs", "patient/Observation.rs")).toBe(
      true,
    );
  });

  it("accepts a narrower permission set", () => {
    expect(covers("patient/Observation.rs", "patient/Observation.r")).toBe(
      true,
    );
    expect(covers("patient/Observation.cruds", "patient/Observation.rs")).toBe(
      true,
    );
    expect(covers("patient/Observation.cruds", "patient/Observation.c")).toBe(
      true,
    );
  });

  it("rejects a wider permission set", () => {
    expect(covers("patient/Observation.r", "patient/Observation.rs")).toBe(
      false,
    );
    expect(covers("patient/Observation.rs", "patient/Observation.cruds")).toBe(
      false,
    );
    expect(covers("patient/Observation.rs", "patient/Observation.c")).toBe(
      false,
    );
  });
});

describe("isScopeSubsetOf - resource type", () => {
  it("lets a wildcard cover a concrete resource type", () => {
    expect(covers("patient/*.rs", "patient/Observation.rs")).toBe(true);
    expect(covers("system/*.cruds", "system/Encounter.cud")).toBe(true);
  });

  it("does not let a concrete resource type cover a wildcard", () => {
    // Otherwise a client allowed only Observation could refresh into everything.
    expect(covers("patient/Observation.rs", "patient/*.rs")).toBe(false);
  });

  it("rejects a different resource type", () => {
    expect(covers("patient/Observation.rs", "patient/Condition.rs")).toBe(
      false,
    );
  });

  it("treats a wildcard as covering itself", () => {
    expect(covers("patient/*.rs", "patient/*.rs")).toBe(true);
  });
});

describe("isScopeSubsetOf - access context", () => {
  it("rejects a different context even when everything else matches", () => {
    expect(covers("patient/Observation.rs", "user/Observation.rs")).toBe(false);
    expect(covers("user/Observation.rs", "system/Observation.rs")).toBe(false);
    expect(covers("system/*.rs", "patient/Observation.rs")).toBe(false);
  });
});

describe("isScopeSubsetOf - search parameter restrictions", () => {
  it("lets an unrestricted scope cover a restricted one", () => {
    expect(
      covers(
        "patient/Observation.rs",
        "patient/Observation.rs?category=laboratory",
      ),
    ).toBe(true);
  });

  it("does not let a restricted scope cover an unrestricted one", () => {
    expect(
      covers(
        "patient/Observation.rs?category=laboratory",
        "patient/Observation.rs",
      ),
    ).toBe(false);
  });

  it("requires a matching restriction value", () => {
    expect(
      covers(
        "patient/Observation.rs?category=laboratory",
        "patient/Observation.rs?category=vital-signs",
      ),
    ).toBe(false);
  });

  it("accepts a candidate that adds further restrictions", () => {
    expect(
      covers(
        "patient/Observation.rs?category=laboratory",
        "patient/Observation.rs?category=laboratory&status=final",
      ),
    ).toBe(true);
  });

  it("ignores restriction ordering", () => {
    expect(
      covers(
        "patient/Observation.rs?category=laboratory&status=final",
        "patient/Observation.rs?status=final&category=laboratory",
      ),
    ).toBe(true);
  });
});

describe("isScopeSubsetOf - non-resource scopes", () => {
  it("compares identity scopes by name", () => {
    expect(covers("openid", "openid")).toBe(true);
    expect(covers("openid", "fhirUser")).toBe(false);
  });

  it("compares refresh scopes by name", () => {
    expect(covers("offline_access", "offline_access")).toBe(true);
    expect(covers("offline_access", "online_access")).toBe(false);
  });

  it("compares launch scopes by context type", () => {
    expect(covers("launch/patient", "launch/patient")).toBe(true);
    expect(covers("launch/patient", "launch/encounter")).toBe(false);
    expect(covers("launch", "launch")).toBe(true);
    expect(covers("launch", "launch/patient")).toBe(false);
  });

  it("compares launch scopes by role", () => {
    expect(
      covers(
        "launch/list?role=https://a.example",
        "launch/list?role=https://a.example",
      ),
    ).toBe(true);
    expect(
      covers(
        "launch/list?role=https://a.example",
        "launch/list?role=https://b.example",
      ),
    ).toBe(false);
    expect(covers("launch/list", "launch/list?role=https://a.example")).toBe(
      false,
    );
  });

  it("compares custom scopes verbatim", () => {
    expect(covers("__darkMode", "__darkMode")).toBe(true);
    expect(covers("__darkMode", "__lightMode")).toBe(false);
  });

  it("never matches across scope kinds", () => {
    expect(covers("openid", "offline_access")).toBe(false);
    expect(covers("patient/Observation.rs", "launch/patient")).toBe(false);
  });
});

describe("isScopeCoveredBy and areScopesCoveredBy", () => {
  const granted = scopes(
    "patient/*.rs launch/patient openid fhirUser offline_access",
  );

  it("finds a covering scope anywhere in the set", () => {
    expect(isScopeCoveredBy(scope("patient/Observation.r"), granted)).toBe(
      true,
    );
    expect(isScopeCoveredBy(scope("openid"), granted)).toBe(true);
  });

  it("returns false when nothing in the set covers the candidate", () => {
    expect(isScopeCoveredBy(scope("patient/Observation.c"), granted)).toBe(
      false,
    );
    expect(isScopeCoveredBy(scope("user/Patient.rs"), granted)).toBe(false);
  });

  it("returns false against an empty set", () => {
    expect(isScopeCoveredBy(scope("openid"), [])).toBe(false);
  });

  it("requires every candidate to be covered", () => {
    expect(
      areScopesCoveredBy(scopes("patient/Observation.rs openid"), granted),
    ).toBe(true);
    expect(
      areScopesCoveredBy(
        scopes("patient/Observation.rs user/Patient.rs"),
        granted,
      ),
    ).toBe(false);
  });

  it("treats an empty candidate list as covered", () => {
    expect(areScopesCoveredBy([], granted)).toBe(true);
  });
});

describe("narrowToPermitted", () => {
  it("drops scopes outside the permitted set, preserving order", () => {
    const permitted = scopes("patient/*.rs openid");
    const requested = scopes(
      "patient/Observation.rs user/Patient.rs openid patient/Condition.c",
    );

    expect(narrowToPermitted(requested, permitted).map(formatScope)).toEqual([
      "patient/Observation.rs",
      "openid",
    ]);
  });

  it("returns everything when all scopes are permitted", () => {
    const permitted = scopes("patient/*.cruds");
    const requested = scopes("patient/Observation.rs patient/Condition.cud");
    expect(narrowToPermitted(requested, permitted)).toHaveLength(2);
  });

  it("returns nothing when the permitted set is empty", () => {
    expect(narrowToPermitted(scopes("patient/Observation.rs"), [])).toEqual([]);
  });
});

describe("refresh token narrowing", () => {
  // On a refresh grant the spec requires the requested scope to be a strict
  // subset of what was originally granted.
  const originallyGranted = scopes(
    "patient/Observation.rs patient/Condition.rs offline_access",
  );

  it("permits requesting a subset of the original grant", () => {
    expect(
      areScopesCoveredBy(scopes("patient/Observation.rs"), originallyGranted),
    ).toBe(true);
    expect(
      areScopesCoveredBy(scopes("patient/Observation.r"), originallyGranted),
    ).toBe(true);
  });

  it("refuses an escalation to a resource never granted", () => {
    expect(
      areScopesCoveredBy(
        scopes("patient/MedicationRequest.rs"),
        originallyGranted,
      ),
    ).toBe(false);
  });

  it("refuses an escalation to a wildcard", () => {
    expect(areScopesCoveredBy(scopes("patient/*.rs"), originallyGranted)).toBe(
      false,
    );
  });

  it("refuses an escalation to a write permission", () => {
    expect(
      areScopesCoveredBy(scopes("patient/Observation.cud"), originallyGranted),
    ).toBe(false);
  });
});
