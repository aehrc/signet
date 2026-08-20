/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { evaluatePolicy } from "./evaluate.js";
import { narrowScopeToPattern, parseScopePattern } from "./pattern.js";
import { PATHLING_PRESET, SMART_BASELINE_PRESET } from "./presets.js";
import { parseScopes } from "../scopes/index.js";
import { formatScope, formatScopes } from "../scopes/serialise.js";

import type { EvaluationContext, PolicyDocument } from "./types.js";
import type { Scope } from "../scopes/types.js";

/** Parses a space-delimited scope string. */
function scopes(raw: string): readonly Scope[] {
  const result = parseScopes(raw);
  if (result.rejected.length > 0) {
    throw new Error(
      `Unexpected rejections: ${result.rejected.map((r) => r.raw).join(", ")}`,
    );
  }
  return result.scopes;
}

/** Parses one scope. */
function scope(raw: string): Scope {
  const [only] = scopes(raw);
  if (only === undefined) {
    throw new Error(`No scope parsed from "${raw}"`);
  }
  return only;
}

/** Parses a pattern, failing the test if it is malformed. */
function pattern(raw: string) {
  const parsed = parseScopePattern(raw);
  if (parsed === undefined) {
    throw new Error(`Pattern "${raw}" did not parse`);
  }
  return parsed;
}

/** An evaluation context with sensible defaults. */
function contextFor(
  requested: string,
  overrides: Partial<EvaluationContext> = {},
): EvaluationContext {
  return {
    endpoint: {
      tenantSlug: "demo",
      slug: "pathling",
      issuer: "https://signet.example.org/t/demo/e/pathling",
      fhirBaseUrl: "https://fhir.example.org/fhir",
    },
    client: { clientId: "app", name: "App", type: "public", attributes: {} },
    user: {
      id: "u1",
      fhirUser: "Practitioner/1",
      displayName: "Dr Who",
      roles: ["practitioner"],
      attributes: {},
    },
    requested: scopes(requested),
    context: { patient: "123" },
    grantType: "authorization_code",
    ...overrides,
  };
}

describe("narrowScopeToPattern", () => {
  it("reduces an over-broad scope to the permitted overlap", () => {
    const narrowed = narrowScopeToPattern(
      scope("patient/Observation.cruds"),
      pattern("patient/*.rs"),
    );
    expect(narrowed && formatScope(narrowed)).toBe("patient/Observation.rs");
  });

  it("returns undefined when the scope already fits, since there is nothing to narrow", () => {
    expect(
      narrowScopeToPattern(
        scope("patient/Observation.rs"),
        pattern("patient/*.rs"),
      ),
    ).toBeUndefined();
    expect(
      narrowScopeToPattern(
        scope("patient/Observation.r"),
        pattern("patient/*.rs"),
      ),
    ).toBeUndefined();
  });

  it("returns undefined when there is no permission overlap at all", () => {
    expect(
      narrowScopeToPattern(
        scope("patient/Observation.cud"),
        pattern("patient/*.rs"),
      ),
    ).toBeUndefined();
  });

  it("returns undefined across a context or resource type mismatch", () => {
    expect(
      narrowScopeToPattern(
        scope("user/Observation.cruds"),
        pattern("patient/*.rs"),
      ),
    ).toBeUndefined();
    expect(
      narrowScopeToPattern(
        scope("patient/Condition.cruds"),
        pattern("patient/Observation.rs"),
      ),
    ).toBeUndefined();
  });

  it("never narrows a non-resource scope", () => {
    expect(
      narrowScopeToPattern(scope("openid"), pattern("patient/*.rs")),
    ).toBeUndefined();
    expect(
      narrowScopeToPattern(scope("launch/patient"), pattern("patient/*.rs")),
    ).toBeUndefined();
  });

  it("preserves search parameter restrictions, which only narrow further", () => {
    const narrowed = narrowScopeToPattern(
      scope("patient/Observation.cruds?category=laboratory"),
      pattern("patient/*.rs"),
    );
    expect(narrowed && formatScope(narrowed)).toBe(
      "patient/Observation.rs?category=laboratory",
    );
  });

  it("keeps permissions in canonical cruds order", () => {
    const narrowed = narrowScopeToPattern(
      scope("patient/Observation.cruds"),
      pattern("patient/*.cruds"),
    );
    // Already fits, so no narrowing; ordering is asserted via a partial overlap.
    expect(narrowed).toBeUndefined();
    const partial = narrowScopeToPattern(
      scope("patient/Observation.cruds"),
      pattern("patient/*.rd"),
    );
    expect(partial && formatScope(partial)).toBe("patient/Observation.rd");
  });
});

describe("evaluatePolicy - narrowing", () => {
  it("degrades an over-broad request to read rather than granting nothing", () => {
    // The failure this prevents: an app asking for patient/*.cruds against a
    // read-only policy used to receive no data scopes at all, and would fail at
    // its first API call instead of working read-only.
    const result = evaluatePolicy(
      PATHLING_PRESET,
      contextFor("launch/patient patient/*.cruds"),
    );
    expect(formatScopes(result.grantedScopes)).toBe(
      "launch/patient patient/*.rs",
    );
    expect(result.claims["authorities"]).toEqual([
      "pathling:read",
      "pathling:search",
      "pathling:read-resource",
      "pathling:export",
      "pathling:sql-run",
      "pathling:sql-export",
      "pathling:jobs",
    ]);
  });

  it("records what was asked for so the decision is auditable", () => {
    const result = evaluatePolicy(
      PATHLING_PRESET,
      contextFor("patient/Observation.cruds"),
    );
    expect(result.narrowedScopes).toHaveLength(1);
    expect(formatScope(result.narrowedScopes[0]!.requested)).toBe(
      "patient/Observation.cruds",
    );
    expect(formatScope(result.narrowedScopes[0]!.granted)).toBe(
      "patient/Observation.rs",
    );
    expect(result.narrowedScopes[0]!.ruleId).toBe("grant-patient-read");
  });

  it("leaves narrowedScopes empty when nothing was reduced", () => {
    const result = evaluatePolicy(
      PATHLING_PRESET,
      contextFor("patient/Observation.rs"),
    );
    expect(result.narrowedScopes).toEqual([]);
  });

  it("still denies a scope with no overlap at all", () => {
    const result = evaluatePolicy(
      PATHLING_PRESET,
      contextFor("patient/Observation.cud"),
    );
    expect(result.grantedScopes).toEqual([]);
    expect(result.deniedScopes).toHaveLength(1);
    expect(result.narrowedScopes).toEqual([]);
  });

  it("narrows for the baseline preset too", () => {
    const result = evaluatePolicy(
      SMART_BASELINE_PRESET,
      contextFor("patient/*.cruds"),
    );
    expect(formatScopes(result.grantedScopes)).toBe("patient/*.rs");
  });

  it("respects requireContext when narrowing", () => {
    // No patient resolved, so the patient-context rule cannot apply and there is
    // nothing to narrow towards.
    const result = evaluatePolicy(
      PATHLING_PRESET,
      contextFor("patient/Observation.cruds", { context: {} }),
    );
    expect(result.grantedScopes).toEqual([]);
    expect(result.narrowedScopes).toEqual([]);
  });

  it("respects grantTypes when narrowing", () => {
    const result = evaluatePolicy(
      PATHLING_PRESET,
      contextFor("system/*.cruds", {
        grantType: "authorization_code",
        user: null,
      }),
    );
    expect(result.grantedScopes).toEqual([]);
  });
});

describe("evaluatePolicy - narrowing cannot escape an explicit deny", () => {
  const withDeny: PolicyDocument = {
    version: 1,
    scopeGrants: [
      { id: "allow-read", match: "patient/*.rs", allow: true, narrow: true },
      { id: "deny-broad", match: "patient/*.cruds", allow: false },
    ],
    claimRules: [],
    contextRules: [],
    defaults: { accessTokenTtl: 300, refreshTokenTtl: 86_400 },
  };

  it("honours a later deny rather than narrowing around it", () => {
    // This is the security-critical ordering: `patient/Observation.cruds` matches
    // the deny rule under `within`, so it must be refused outright. Narrowing is
    // only ever a fallback for a scope that matched no rule.
    const result = evaluatePolicy(
      withDeny,
      contextFor("patient/Observation.cruds"),
    );
    expect(result.grantedScopes).toEqual([]);
    expect(result.narrowedScopes).toEqual([]);
    expect(result.deniedScopes[0]?.ruleId).toBe("deny-broad");
  });

  it("still grants a scope the allow rule covers outright", () => {
    const result = evaluatePolicy(
      withDeny,
      contextFor("patient/Observation.rs"),
    );
    expect(formatScopes(result.grantedScopes)).toBe("patient/Observation.rs");
  });

  it("does not narrow when the rule has not opted in", () => {
    const noOptIn: PolicyDocument = {
      ...withDeny,
      scopeGrants: [{ id: "allow-read", match: "patient/*.rs", allow: true }],
    };
    const result = evaluatePolicy(
      noOptIn,
      contextFor("patient/Observation.cruds"),
    );
    expect(result.grantedScopes).toEqual([]);
    expect(result.deniedScopes).toHaveLength(1);
  });

  it("does not narrow towards a rule that itself denies", () => {
    const denyNarrow: PolicyDocument = {
      ...withDeny,
      scopeGrants: [
        { id: "deny-read", match: "patient/*.rs", allow: false, narrow: true },
      ],
    };
    const result = evaluatePolicy(
      denyNarrow,
      contextFor("patient/Observation.cud"),
    );
    expect(result.grantedScopes).toEqual([]);
  });
});
