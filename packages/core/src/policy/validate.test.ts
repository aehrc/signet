/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  PATHLING_PRESET,
  POLICY_PRESETS,
  SMART_BASELINE_PRESET,
} from "./presets.js";
import { validatePolicy } from "./validate.js";

import type { PolicyIssue } from "./types.js";

/** A minimal valid document, as plain JSON-shaped data. */
function minimal(): Record<string, unknown> {
  return {
    version: 1,
    scopeGrants: [],
    claimRules: [],
    contextRules: [],
    defaults: { accessTokenTtl: 3600, refreshTokenTtl: 86_400 },
  };
}

/** Validates and returns the issues, failing if the document was accepted. */
function issues(input: unknown): readonly PolicyIssue[] {
  const result = validatePolicy(input);
  if (result.ok) {
    throw new Error("Expected the document to be rejected");
  }
  return result.issues;
}

/** The issue paths reported for a document. */
function paths(input: unknown): readonly string[] {
  return issues(input).map((issue) => issue.path);
}

/** The issues reported for a document, empty when it was accepted. */
function report(input: unknown): readonly PolicyIssue[] {
  const result = validatePolicy(input);
  return result.ok ? [] : result.issues;
}

/** Builds a document with a single grant rule. */
function withGrant(rule: unknown): Record<string, unknown> {
  return { ...minimal(), scopeGrants: [rule] };
}

/** Builds a document with a single claim rule condition. */
function withCondition(when: unknown): Record<string, unknown> {
  return { ...minimal(), claimRules: [{ when, emit: {} }] };
}

/** Builds a document with a single claim rule emit block. */
function withEmit(emit: unknown): Record<string, unknown> {
  return { ...minimal(), claimRules: [{ when: {}, emit }] };
}

/** Builds a document with a single mapping rule. */
function withMapping(rule: unknown): Record<string, unknown> {
  return { ...minimal(), scopeMappings: [rule] };
}

describe("validatePolicy - document shape", () => {
  it("accepts a minimal document", () => {
    expect(report(minimal())).toEqual([]);
  });

  it("returns the document itself on success", () => {
    const input = minimal();
    const result = validatePolicy(input);
    // Identity, not equality: a caller holds the object it passed in, and a
    // validator that returned a copy would leave it holding the wrong one. Widened
    // to `unknown` because the comparison is of references, and the two sides are
    // the same object described by two different types.
    expect<unknown>(result.ok && result.policy).toBe(input);
  });

  // Each case is wrapped in a one-element tuple because `each` spreads an array
  // case across the callback's parameters: a bare `[]` would arrive as no
  // arguments at all, and the runner would read the unfilled parameter as a
  // `done` callback and wait for it.
  it.each([[null], [undefined], [1], ["policy"], [true], [[]]])(
    "rejects %j as a document",
    (input) => {
      expect(issues(input)).toEqual([
        { path: "", message: "Policy must be an object" },
      ]);
    },
  );

  it("rejects unknown top level keys", () => {
    expect(paths({ ...minimal(), extra: true, another: 1 })).toEqual([
      "extra",
      "another",
    ]);
  });

  it.each([undefined, 0, 2, "1", null])("rejects version %j", (version) => {
    expect(paths({ ...minimal(), version })).toContain("version");
  });

  it("requires each rule collection to be an array", () => {
    expect(paths({ ...minimal(), scopeGrants: undefined })).toContain(
      "scopeGrants",
    );
    expect(paths({ ...minimal(), claimRules: {} })).toContain("claimRules");
    expect(paths({ ...minimal(), contextRules: "no" })).toContain(
      "contextRules",
    );
  });

  it("treats scopeMappings as optional but validates it when present", () => {
    expect(report(minimal())).toEqual([]);
    expect(paths({ ...minimal(), scopeMappings: {} })).toContain(
      "scopeMappings",
    );
  });

  it("requires each rule to be an object", () => {
    expect(paths({ ...minimal(), scopeGrants: ["nope"] })).toEqual([
      "scopeGrants[0]",
    ]);
  });
});

describe("validatePolicy - defaults", () => {
  it.each([
    ["a missing block", undefined],
    ["a non-object block", 3600],
  ])("rejects %s", (_label, defaults) => {
    expect(paths({ ...minimal(), defaults })).toContain("defaults");
  });

  it.each([0, -1, 1.5, "3600", null, Number.NaN])(
    "rejects the TTL %j",
    (accessTokenTtl) => {
      expect(
        paths({
          ...minimal(),
          defaults: { accessTokenTtl, refreshTokenTtl: 86_400 },
        }),
      ).toContain("defaults.accessTokenTtl");
    },
  );

  it("requires both lifetimes", () => {
    expect(
      paths({ ...minimal(), defaults: { accessTokenTtl: 3600 } }),
    ).toContain("defaults.refreshTokenTtl");
  });

  it("rejects unknown keys in defaults", () => {
    expect(
      paths({
        ...minimal(),
        defaults: { accessTokenTtl: 1, refreshTokenTtl: 1, idTokenTtl: 1 },
      }),
    ).toContain("defaults.idTokenTtl");
  });
});

describe("validatePolicy - scope grant rules", () => {
  it("accepts a fully specified rule", () => {
    expect(
      report(
        withGrant({
          id: "grant-1",
          description: "Reads",
          enabled: true,
          match: "patient/*.rs",
          allow: true,
          requireContext: ["patient", "encounter"],
          requireUserRole: ["clinician"],
          grantTypes: ["authorization_code", "refresh_token"],
          clientTypes: ["public", "confidential-symmetric"],
        }),
      ),
    ).toEqual([]);
  });

  it.each([
    "patient/*.rs",
    "*/*.cruds",
    "system/Observation.r",
    "*/Patient.read",
    "openid",
    "fhirUser",
    "profile",
    "launch",
    "launch/patient",
    "offline_access",
    "online_access",
    "__custom.manage",
    "https://example.org/scopes/admin",
    "patient/Observation.rs?category=laboratory",
  ])("accepts the match expression %s", (match) => {
    expect(report(withGrant({ match, allow: true }))).toEqual([]);
  });

  it.each([
    "",
    "nonsense",
    "admin/*.r",
    "patient/*",
    "patient/*.x",
    "patient/observation.r",
  ])("rejects the match expression %j", (match) => {
    expect(paths(withGrant({ match, allow: true }))).toContain(
      "scopeGrants[0].match",
    );
  });

  it("rejects a non-canonical scope used as an exact match", () => {
    // `patient/Observation.read?x=y` would be compared against the canonical
    // `.rs` form and could never match, so it is refused with advice.
    const reported = issues(
      withGrant({ match: "patient/Observation.read?x=y", allow: true }),
    );
    expect(reported[0]?.path).toBe("scopeGrants[0].match");
    expect(reported[0]?.message).toContain("patient/Observation.rs?x=y");
  });

  it("requires a boolean allow", () => {
    expect(paths(withGrant({ match: "*/*.r" }))).toContain(
      "scopeGrants[0].allow",
    );
    expect(paths(withGrant({ match: "*/*.r", allow: "yes" }))).toContain(
      "scopeGrants[0].allow",
    );
  });

  it("rejects unknown keys on a rule", () => {
    expect(
      paths(withGrant({ match: "*/*.r", allow: true, matches: "*/*.r" })),
    ).toContain("scopeGrants[0].matches");
  });

  it("validates requireContext entries", () => {
    expect(
      paths(
        withGrant({
          match: "*/*.r",
          allow: true,
          requireContext: ["patient", "tenant"],
        }),
      ),
    ).toContain("scopeGrants[0].requireContext[1]");
    expect(
      paths(
        withGrant({ match: "*/*.r", allow: true, requireContext: "patient" }),
      ),
    ).toContain("scopeGrants[0].requireContext");
  });

  it("validates grantTypes and clientTypes entries", () => {
    expect(
      paths(
        withGrant({ match: "*/*.r", allow: true, grantTypes: ["password"] }),
      ),
    ).toContain("scopeGrants[0].grantTypes[0]");
    expect(
      paths(
        withGrant({ match: "*/*.r", allow: true, clientTypes: ["secret"] }),
      ),
    ).toContain("scopeGrants[0].clientTypes[0]");
  });

  it("validates requireUserRole entries", () => {
    expect(
      paths(withGrant({ match: "*/*.r", allow: true, requireUserRole: [""] })),
    ).toContain("scopeGrants[0].requireUserRole[0]");
    expect(
      paths(withGrant({ match: "*/*.r", allow: true, requireUserRole: [1] })),
    ).toContain("scopeGrants[0].requireUserRole[0]");
    expect(
      paths(
        withGrant({
          match: "*/*.r",
          allow: true,
          requireUserRole: "clinician",
        }),
      ),
    ).toContain("scopeGrants[0].requireUserRole");
  });

  it("validates rule metadata", () => {
    expect(paths(withGrant({ match: "*/*.r", allow: true, id: "" }))).toContain(
      "scopeGrants[0].id",
    );
    expect(paths(withGrant({ match: "*/*.r", allow: true, id: 1 }))).toContain(
      "scopeGrants[0].id",
    );
    expect(
      paths(withGrant({ match: "*/*.r", allow: true, description: 1 })),
    ).toContain("scopeGrants[0].description");
    expect(
      paths(withGrant({ match: "*/*.r", allow: true, enabled: "no" })),
    ).toContain("scopeGrants[0].enabled");
  });
});

describe("validatePolicy - rule ids", () => {
  it("accepts rules with no ids at all", () => {
    expect(
      report({
        ...minimal(),
        scopeGrants: [
          { match: "*/*.r", allow: true },
          { match: "*/*.s", allow: true },
        ],
      }),
    ).toEqual([]);
  });

  it("rejects a duplicate id within a collection", () => {
    const reported = issues({
      ...minimal(),
      scopeGrants: [
        { id: "same", match: "*/*.r", allow: true },
        { id: "same", match: "*/*.s", allow: true },
      ],
    });
    expect(reported[0]?.path).toBe("scopeGrants[1].id");
    expect(reported[0]?.message).toContain("scopeGrants[0]");
  });

  it("rejects a duplicate id across collections", () => {
    expect(
      paths({
        ...minimal(),
        scopeGrants: [{ id: "same", match: "*/*.r", allow: true }],
        claimRules: [{ id: "same", when: {}, emit: {} }],
      }),
    ).toEqual(["claimRules[0].id"]);
  });
});

describe("validatePolicy - conditions", () => {
  it("accepts every condition field", () => {
    expect(
      report(
        withCondition({
          always: true,
          scope: "patient/*.rs",
          context: ["patient", "encounter", "fhirContext", "needPatientBanner"],
          grantTypes: ["client_credentials"],
          clientTypes: ["confidential-asymmetric"],
          userRole: ["admin"],
          hasUser: false,
        }),
      ),
    ).toEqual([]);
  });

  it("requires a condition on a claim rule", () => {
    expect(paths({ ...minimal(), claimRules: [{ emit: {} }] })).toContain(
      "claimRules[0].when",
    );
  });

  it("does not require a condition on a context rule", () => {
    expect(report({ ...minimal(), contextRules: [{ emit: {} }] })).toEqual([]);
  });

  it("rejects a non-object condition", () => {
    expect(paths(withCondition("always"))).toContain("claimRules[0].when");
  });

  it("rejects unknown condition keys", () => {
    expect(paths(withCondition({ scopes: "openid" }))).toContain(
      "claimRules[0].when.scopes",
    );
  });

  it("validates the scope condition as a match expression", () => {
    expect(paths(withCondition({ scope: "nonsense" }))).toContain(
      "claimRules[0].when.scope",
    );
    expect(report(withCondition({ scope: "openid" }))).toEqual([]);
  });

  it("validates the launch context keys", () => {
    expect(paths(withCondition({ context: ["patient", "nope"] }))).toContain(
      "claimRules[0].when.context[1]",
    );
  });

  it("validates the boolean fields", () => {
    expect(paths(withCondition({ always: "yes" }))).toContain(
      "claimRules[0].when.always",
    );
    expect(paths(withCondition({ hasUser: 1 }))).toContain(
      "claimRules[0].when.hasUser",
    );
  });
});

describe("validatePolicy - emit templates", () => {
  it("accepts literals and templates", () => {
    expect(
      report(
        withEmit({
          patient_id: "{{ context.patient }}",
          banner: true,
          count: 3,
          nothing: null,
          list: ["{{ endpoint.slug }}", "literal"],
          nested: { ref: "{{ context.encounter }}" },
        }),
      ),
    ).toEqual([]);
  });

  it("rejects a non-object emit block", () => {
    expect(paths(withEmit("patient"))).toContain("claimRules[0].emit");
    expect(paths(withEmit([]))).toContain("claimRules[0].emit");
  });

  it("reports the precise path of an offending claim", () => {
    expect(
      paths({
        ...minimal(),
        claimRules: [
          { when: {}, emit: {} },
          { when: {}, emit: {} },
          { when: {}, emit: { patient_id: "{{ context.patient | explode }}" } },
        ],
      }),
    ).toEqual(["claimRules[2].emit.patient_id"]);
  });

  it("reports a path inside a nested claim value", () => {
    expect(
      paths(withEmit({ outer: { list: ["ok", "{{ x | explode }}"] } })),
    ).toEqual(["claimRules[0].emit.outer.list[1]"]);
  });

  it("rejects an unknown filter", () => {
    const reported = issues(withEmit({ a: "{{ user.id | shred }}" }));
    expect(reported[0]?.message).toBe('Unknown template filter "shred"');
  });

  it.each([
    "join",
    "join:,",
    'join:", "',
    "first",
    "default:none",
    "lower",
    "upper",
    "stripPrefix:Patient/",
  ])("accepts the filter %s", (filter) => {
    expect(report(withEmit({ a: `{{ user.id | ${filter} }}` }))).toEqual([]);
  });

  it("requires an argument for the filters that need one", () => {
    expect(issues(withEmit({ a: "{{ user.id | default }}" }))[0]?.message).toBe(
      'Filter "default" requires an argument',
    );
    expect(
      issues(withEmit({ a: "{{ user.id | stripPrefix }}" }))[0]?.message,
    ).toBe('Filter "stripPrefix" requires an argument');
  });

  it("refuses an argument for the filters that take none", () => {
    expect(issues(withEmit({ a: "{{ user.id | upper:x }}" }))[0]?.message).toBe(
      'Filter "upper" does not take an argument',
    );
  });

  it("rejects an interpolation with no path", () => {
    expect(issues(withEmit({ a: "{{ }}" }))[0]?.message).toContain(
      "has no path",
    );
    expect(issues(withEmit({ a: "{{ | upper }}" }))[0]?.message).toContain(
      "has no path",
    );
  });

  it("rejects an unterminated interpolation", () => {
    expect(issues(withEmit({ a: "{{ user.id" }))[0]?.message).toBe(
      'Unterminated "{{" in template',
    );
  });

  it("rejects a path that could never resolve", () => {
    for (const path of ["1 + 1", "user id", "user..id", "user.id!"]) {
      expect(issues(withEmit({ a: `{{ ${path} }}` }))[0]?.message).toContain(
        "Invalid path segment",
      );
    }
  });

  it("accepts a literal string with no interpolation", () => {
    expect(report(withEmit({ a: "pathling:search" }))).toEqual([]);
  });

  it("rejects a non-JSON claim value", () => {
    expect(paths(withEmit({ a: Number.NaN }))).toEqual([
      "claimRules[0].emit.a",
    ]);
    expect(paths(withEmit({ a: undefined }))).toEqual(["claimRules[0].emit.a"]);
  });

  it("rejects an empty claim name", () => {
    expect(paths(withEmit({ "": "x" }))).toEqual(["claimRules[0].emit"]);
  });
});

describe("validatePolicy - scope mapping rules", () => {
  it("accepts a fully specified rule", () => {
    expect(
      report(
        withMapping({
          id: "pathling-read",
          description: "Read authority",
          enabled: true,
          when: { grantTypes: ["client_credentials"] },
          forEachScope: "*/*.rs",
          appendTo: "authorities",
          values: ["pathling:read{{ scope.resourceTypeSuffix }}"],
        }),
      ),
    ).toEqual([]);
  });

  it("requires a valid forEachScope", () => {
    expect(
      paths(
        withMapping({ forEachScope: "nope", appendTo: "a", values: ["v"] }),
      ),
    ).toContain("scopeMappings[0].forEachScope");
  });

  it("requires a non-empty appendTo", () => {
    for (const appendTo of [undefined, "", 1, null]) {
      expect(
        paths(withMapping({ forEachScope: "*/*.r", appendTo, values: ["v"] })),
      ).toContain("scopeMappings[0].appendTo");
    }
  });

  it("requires a non-empty values array", () => {
    for (const values of [undefined, [], "v", {}]) {
      expect(
        paths(withMapping({ forEachScope: "*/*.r", appendTo: "a", values })),
      ).toContain("scopeMappings[0].values");
    }
  });

  it("validates each value as a template", () => {
    expect(
      paths(
        withMapping({
          forEachScope: "*/*.r",
          appendTo: "a",
          values: ["ok", "{{ scope.resourceType | explode }}"],
        }),
      ),
    ).toEqual(["scopeMappings[0].values[1]"]);
    expect(
      paths(withMapping({ forEachScope: "*/*.r", appendTo: "a", values: [1] })),
    ).toEqual(["scopeMappings[0].values[0]"]);
  });

  it("rejects unknown keys", () => {
    expect(
      paths(
        withMapping({
          forEachScope: "*/*.r",
          appendTo: "a",
          values: ["v"],
          appendToClaim: "a",
        }),
      ),
    ).toContain("scopeMappings[0].appendToClaim");
  });
});

describe("validatePolicy - reporting", () => {
  it("reports every problem at once, not just the first", () => {
    const reported = issues({
      version: 2,
      scopeGrants: [{ match: "nope", allow: "yes" }],
      claimRules: [{ when: {}, emit: { a: "{{ x | explode }}" } }],
      contextRules: [],
      defaults: { accessTokenTtl: 0, refreshTokenTtl: -1 },
    });
    expect(reported.map((issue) => issue.path)).toEqual([
      "version",
      "scopeGrants[0].match",
      "scopeGrants[0].allow",
      "claimRules[0].emit.a",
      "defaults.accessTokenTtl",
      "defaults.refreshTokenTtl",
    ]);
  });
});

describe("validatePolicy - presets", () => {
  it.each(POLICY_PRESETS.map((preset) => [preset.id, preset.policy] as const))(
    "accepts the %s preset",
    (_id, document) => {
      expect(report(document)).toEqual([]);
    },
  );

  it("accepts both presets after a JSON round trip", () => {
    for (const document of [SMART_BASELINE_PRESET, PATHLING_PRESET]) {
      const serialised = JSON.stringify(document);
      expect(report(JSON.parse(serialised))).toEqual([]);
    }
  });
});
