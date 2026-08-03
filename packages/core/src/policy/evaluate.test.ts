import { describe, expect, it } from "vitest";

import { evaluatePolicy } from "./evaluate.js";
import { formatScope, parseScopes } from "../scopes/index.js";

import type {
  ClaimRule,
  ContextRule,
  EvaluationContext,
  EvaluationUser,
  GrantType,
  PolicyDocument,
  ScopeGrantRule,
  ScopeMappingRule,
} from "./types.js";
import type { LaunchContext } from "../launch/types.js";
import type { Scope } from "../scopes/types.js";

/** Parses a space-delimited scope string, failing on anything unparseable. */
function scopes(raw: string): readonly Scope[] {
  const result = parseScopes(raw);
  if (result.rejected.length > 0) {
    throw new Error(
      `Unexpected rejections: ${result.rejected.map((entry) => entry.raw).join(", ")}`,
    );
  }
  return result.scopes;
}

/** The parts of an evaluation context a test may vary. */
interface ContextOverrides {
  readonly requested?: string;
  readonly context?: LaunchContext;
  readonly user?: EvaluationUser | null;
  readonly grantType?: GrantType;
  readonly clientType?: EvaluationContext["client"]["type"];
}

const USER: EvaluationUser = {
  id: "u1",
  fhirUser: "Practitioner/abc",
  displayName: "Dr Example",
  roles: ["clinician"],
  attributes: { department: "Cardiology" },
};

/** Builds an evaluation context with sensible defaults. */
function context(overrides: ContextOverrides = {}): EvaluationContext {
  return {
    endpoint: {
      tenantSlug: "demo",
      slug: "pathling",
      issuer: "https://signet.example.org/t/demo/e/pathling",
      fhirBaseUrl: "https://fhir.example.org/fhir",
    },
    client: {
      clientId: "client-1",
      name: "Test client",
      type: overrides.clientType ?? "public",
      attributes: { vendor: "acme" },
    },
    user: overrides.user === undefined ? USER : overrides.user,
    requested: scopes(overrides.requested ?? ""),
    context: overrides.context ?? {},
    grantType: overrides.grantType ?? "authorization_code",
  };
}

/** The parts of a policy document a test may vary. */
interface PolicyOverrides {
  readonly scopeGrants?: readonly ScopeGrantRule[];
  readonly claimRules?: readonly ClaimRule[];
  readonly scopeMappings?: readonly ScopeMappingRule[];
  readonly contextRules?: readonly ContextRule[];
  readonly accessTokenTtl?: number;
  readonly refreshTokenTtl?: number;
}

/** Builds a policy document with sensible defaults. */
function policy(overrides: PolicyOverrides = {}): PolicyDocument {
  return {
    version: 1,
    scopeGrants: overrides.scopeGrants ?? [{ match: "*/*.cruds", allow: true }],
    claimRules: overrides.claimRules ?? [],
    ...(overrides.scopeMappings === undefined
      ? {}
      : { scopeMappings: overrides.scopeMappings }),
    contextRules: overrides.contextRules ?? [],
    defaults: {
      accessTokenTtl: overrides.accessTokenTtl ?? 3600,
      refreshTokenTtl: overrides.refreshTokenTtl ?? 86_400,
    },
  };
}

/** The granted scopes, as canonical strings. */
function granted(
  overrides: PolicyOverrides,
  contextOverrides: ContextOverrides,
): readonly string[] {
  return evaluatePolicy(
    policy(overrides),
    context(contextOverrides),
  ).grantedScopes.map((scope) => formatScope(scope));
}

describe("evaluatePolicy — scope grants", () => {
  it("grants a scope the first matching rule allows", () => {
    expect(
      granted(
        { scopeGrants: [{ match: "patient/*.rs", allow: true }] },
        { requested: "patient/Observation.r patient/Condition.rs" },
      ),
    ).toEqual(["patient/Observation.r", "patient/Condition.rs"]);
  });

  it("denies a scope no rule matches, defaulting to refusal", () => {
    const result = evaluatePolicy(
      policy({ scopeGrants: [{ match: "patient/*.rs", allow: true }] }),
      context({ requested: "patient/Observation.cud" }),
    );
    expect(result.grantedScopes).toEqual([]);
    expect(result.deniedScopes).toHaveLength(1);
    expect(result.deniedScopes[0]?.reason).toBe(
      "No grant rule matches this scope, and the default is to deny",
    );
    expect(result.deniedScopes[0]?.ruleId).toBeUndefined();
  });

  it("denies everything when there are no grant rules at all", () => {
    const result = evaluatePolicy(
      policy({ scopeGrants: [] }),
      context({ requested: "patient/Observation.r openid launch/patient" }),
    );
    expect(result.grantedScopes).toEqual([]);
    expect(result.deniedScopes).toHaveLength(3);
  });

  it("stops at the first matching rule, even when a later rule would allow", () => {
    expect(
      granted(
        {
          scopeGrants: [
            { id: "deny-writes", match: "*/*.cud", allow: false },
            { match: "*/*.cruds", allow: true },
          ],
        },
        { requested: "patient/Observation.cud patient/Observation.rs" },
      ),
    ).toEqual(["patient/Observation.rs"]);
  });

  it("records the deciding rule id and a readable reason on a denial", () => {
    const result = evaluatePolicy(
      policy({
        scopeGrants: [{ id: "no-deletes", match: "*/*.d", allow: false }],
      }),
      context({ requested: "patient/Observation.d" }),
    );
    expect(result.deniedScopes[0]).toEqual({
      scope: result.deniedScopes[0]?.scope,
      reason: 'Denied by rule no-deletes matching "*/*.d"',
      ruleId: "no-deletes",
    });
  });

  it("names the rule by index when it has no id", () => {
    const result = evaluatePolicy(
      policy({
        scopeGrants: [
          { match: "system/*.r", allow: true },
          { match: "*/*.d", allow: false },
        ],
      }),
      context({ requested: "patient/Observation.d" }),
    );
    expect(result.deniedScopes[0]?.reason).toBe(
      'Denied by rule scopeGrants[1] matching "*/*.d"',
    );
    expect(result.deniedScopes[0]?.ruleId).toBeUndefined();
  });

  it("skips disabled rules entirely", () => {
    expect(
      granted(
        {
          scopeGrants: [
            { id: "off", match: "*/*.cruds", allow: true, enabled: false },
            { match: "patient/*.r", allow: true },
          ],
        },
        { requested: "patient/Observation.r patient/Observation.c" },
      ),
    ).toEqual(["patient/Observation.r"]);
  });

  it("treats a disabled deny rule as absent", () => {
    expect(
      granted(
        {
          scopeGrants: [
            { match: "*/*.d", allow: false, enabled: false },
            { match: "*/*.cruds", allow: true },
          ],
        },
        { requested: "patient/Observation.d" },
      ),
    ).toEqual(["patient/Observation.d"]);
  });

  it("falls through to the next rule when requireContext is unmet", () => {
    const overrides: PolicyOverrides = {
      scopeGrants: [
        {
          id: "with-patient",
          match: "patient/*.rs",
          allow: true,
          requireContext: ["patient"],
        },
        { id: "fallback", match: "patient/*.r", allow: false },
      ],
    };
    expect(granted(overrides, { requested: "patient/Observation.r" })).toEqual(
      [],
    );
    expect(
      granted(overrides, {
        requested: "patient/Observation.r",
        context: { patient: "Patient/123" },
      }),
    ).toEqual(["patient/Observation.r"]);
  });

  it("treats an empty context value as absent", () => {
    expect(
      granted(
        {
          scopeGrants: [
            { match: "patient/*.rs", allow: true, requireContext: ["patient"] },
          ],
        },
        { requested: "patient/Observation.r", context: { patient: "" } },
      ),
    ).toEqual([]);
  });

  it("requires every listed context key", () => {
    const overrides: PolicyOverrides = {
      scopeGrants: [
        {
          match: "patient/*.rs",
          allow: true,
          requireContext: ["patient", "encounter"],
        },
      ],
    };
    expect(
      granted(overrides, {
        requested: "patient/Observation.r",
        context: { patient: "Patient/123" },
      }),
    ).toEqual([]);
    expect(
      granted(overrides, {
        requested: "patient/Observation.r",
        context: { patient: "Patient/123", encounter: "Encounter/456" },
      }),
    ).toEqual(["patient/Observation.r"]);
  });

  it("honours requireUserRole", () => {
    const overrides: PolicyOverrides = {
      scopeGrants: [
        {
          match: "user/*.cruds",
          allow: true,
          requireUserRole: ["admin", "steward"],
        },
      ],
    };
    expect(granted(overrides, { requested: "user/Patient.cud" })).toEqual([]);
    expect(
      granted(overrides, {
        requested: "user/Patient.cud",
        user: { ...USER, roles: ["clinician", "steward"] },
      }),
    ).toEqual(["user/Patient.cud"]);
  });

  it("never satisfies requireUserRole without a user", () => {
    expect(
      granted(
        {
          scopeGrants: [
            { match: "system/*.rs", allow: true, requireUserRole: ["admin"] },
          ],
        },
        {
          requested: "system/Patient.r",
          user: null,
          grantType: "client_credentials",
        },
      ),
    ).toEqual([]);
  });

  it("honours grantTypes", () => {
    const overrides: PolicyOverrides = {
      scopeGrants: [
        {
          match: "system/*.rs",
          allow: true,
          grantTypes: ["client_credentials"],
        },
      ],
    };
    expect(granted(overrides, { requested: "system/Patient.r" })).toEqual([]);
    expect(
      granted(overrides, {
        requested: "system/Patient.r",
        grantType: "client_credentials",
      }),
    ).toEqual(["system/Patient.r"]);
  });

  it("honours clientTypes", () => {
    const overrides: PolicyOverrides = {
      scopeGrants: [
        {
          match: "*/*.cruds",
          allow: true,
          clientTypes: ["confidential-asymmetric"],
        },
      ],
    };
    expect(granted(overrides, { requested: "user/Patient.r" })).toEqual([]);
    expect(
      granted(overrides, {
        requested: "user/Patient.r",
        clientType: "confidential-asymmetric",
      }),
    ).toEqual(["user/Patient.r"]);
  });

  it("never matches a rule whose condition list is empty", () => {
    expect(
      granted(
        { scopeGrants: [{ match: "*/*.cruds", allow: true, grantTypes: [] }] },
        { requested: "user/Patient.r" },
      ),
    ).toEqual([]);
  });
});

describe("evaluatePolicy — non-resource scopes", () => {
  it("grants a non-resource scope only through an exact match rule", () => {
    expect(
      granted(
        {
          scopeGrants: [
            { match: "*/*.cruds", allow: true },
            { match: "openid", allow: true },
            { match: "launch/patient", allow: true },
            { match: "offline_access", allow: true },
          ],
        },
        {
          requested:
            "openid fhirUser launch/patient launch/encounter offline_access online_access patient/Observation.r",
        },
      ),
    ).toEqual([
      "openid",
      "launch/patient",
      "offline_access",
      "patient/Observation.r",
    ]);
  });

  it("denies every non-resource scope when only resource patterns are configured", () => {
    const result = evaluatePolicy(
      policy({ scopeGrants: [{ match: "*/*.cruds", allow: true }] }),
      context({
        requested: "openid fhirUser profile launch offline_access __custom.x",
      }),
    );
    expect(result.grantedScopes).toEqual([]);
    expect(result.deniedScopes).toHaveLength(6);
  });

  it("can deny a non-resource scope explicitly", () => {
    const result = evaluatePolicy(
      policy({
        scopeGrants: [
          { id: "no-refresh", match: "offline_access", allow: false },
          { match: "offline_access", allow: true },
        ],
      }),
      context({ requested: "offline_access" }),
    );
    expect(result.grantedScopes).toEqual([]);
    expect(result.deniedScopes[0]?.ruleId).toBe("no-refresh");
  });

  it("applies conditions to an exact match rule as well", () => {
    const overrides: PolicyOverrides = {
      scopeGrants: [
        {
          match: "offline_access",
          allow: true,
          clientTypes: ["confidential-symmetric"],
        },
      ],
    };
    expect(granted(overrides, { requested: "offline_access" })).toEqual([]);
    expect(
      granted(overrides, {
        requested: "offline_access",
        clientType: "confidential-symmetric",
      }),
    ).toEqual(["offline_access"]);
  });

  it("matches a bare launch scope distinctly from launch/patient", () => {
    expect(
      granted(
        { scopeGrants: [{ match: "launch", allow: true }] },
        { requested: "launch launch/patient" },
      ),
    ).toEqual(["launch"]);
  });

  it("matches a custom scope by exact equality", () => {
    expect(
      granted(
        {
          scopeGrants: [
            { match: "https://example.org/scopes/admin", allow: true },
          ],
        },
        { requested: "https://example.org/scopes/admin __other.manage" },
      ),
    ).toEqual(["https://example.org/scopes/admin"]);
  });

  it("matches a parameter-restricted scope by exact equality", () => {
    // The `?` clause makes this unparseable as a pattern, so it falls through to
    // exact comparison against the canonical scope string.
    expect(
      granted(
        {
          scopeGrants: [
            {
              match: "patient/Observation.rs?category=laboratory",
              allow: true,
            },
          ],
        },
        {
          requested:
            "patient/Observation.rs?category=laboratory patient/Observation.rs?category=vital-signs",
        },
      ),
    ).toEqual(["patient/Observation.rs?category=laboratory"]);
  });

  it("ignores a duplicated requested scope", () => {
    const result = evaluatePolicy(
      policy({ scopeGrants: [{ match: "patient/*.r", allow: true }] }),
      context({
        requested:
          "patient/Observation.r patient/Observation.r patient/Observation.c patient/Observation.c",
      }),
    );
    expect(result.grantedScopes).toHaveLength(1);
    expect(result.deniedScopes).toHaveLength(1);
  });

  it("normalises v1 scopes before deciding, so v1 and v2 forms agree", () => {
    expect(
      granted(
        { scopeGrants: [{ match: "patient/*.rs", allow: true }] },
        { requested: "patient/Observation.read" },
      ),
    ).toEqual(["patient/Observation.rs"]);
  });
});

describe("evaluatePolicy — claim rules", () => {
  it("emits a claim from a template", () => {
    const result = evaluatePolicy(
      policy({
        claimRules: [
          {
            when: { always: true },
            emit: { patient_id: "{{ context.patient }}" },
          },
        ],
      }),
      context({ context: { patient: "Patient/123" } }),
    );
    expect(result.claims).toEqual({ patient_id: "Patient/123" });
  });

  it("drops a claim whose template does not resolve, rather than emitting null", () => {
    const result = evaluatePolicy(
      policy({
        claimRules: [
          {
            when: { always: true },
            emit: { patient_id: "{{ context.patient }}" },
          },
        ],
      }),
      context(),
    );
    expect(result.claims).toEqual({});
    expect("patient_id" in result.claims).toBe(false);
  });

  it("lets a later rule overwrite an earlier one", () => {
    const result = evaluatePolicy(
      policy({
        claimRules: [
          { when: { always: true }, emit: { role: "base" } },
          { when: { always: true }, emit: { role: "override" } },
        ],
      }),
      context(),
    );
    expect(result.claims["role"]).toBe("override");
  });

  it("leaves an earlier value in place when a later template does not resolve", () => {
    const result = evaluatePolicy(
      policy({
        claimRules: [
          { when: { always: true }, emit: { banner: true } },
          { when: { always: true }, emit: { banner: "{{ context.missing }}" } },
        ],
      }),
      context(),
    );
    expect(result.claims["banner"]).toBe(true);
  });

  it("emits literal values untouched, including a deliberate null", () => {
    const result = evaluatePolicy(
      policy({
        claimRules: [
          {
            when: { always: true },
            emit: { flag: false, count: 3, nothing: null, list: ["a", "b"] },
          },
        ],
      }),
      context(),
    );
    expect(result.claims).toEqual({
      flag: false,
      count: 3,
      nothing: null,
      list: ["a", "b"],
    });
  });

  it("skips a disabled rule", () => {
    const result = evaluatePolicy(
      policy({
        claimRules: [
          { enabled: false, when: { always: true }, emit: { a: "1" } },
          { enabled: true, when: { always: true }, emit: { b: "2" } },
        ],
      }),
      context(),
    );
    expect(result.claims).toEqual({ b: "2" });
  });

  it("exposes the whole evaluation context to templates", () => {
    const result = evaluatePolicy(
      policy({
        claimRules: [
          {
            when: { always: true },
            emit: {
              tenant: "{{ endpoint.tenantSlug }}",
              audience: "{{ endpoint.fhirBaseUrl }}",
              issuer: "{{ endpoint.issuer }}",
              client: "{{ client.clientId }}",
              client_name: "{{ client.name }}",
              client_type: "{{ client.type }}",
              vendor: "{{ client.attributes.vendor }}",
              grant: "{{ grantType }}",
              subject: "{{ user.id }}",
              roles: "{{ user.roles }}",
              department: "{{ user.attributes.department }}",
              scope: "{{ granted | join }}",
              endpoint_slug: "{{ endpoint.slug }}",
            },
          },
        ],
      }),
      context({ requested: "patient/Observation.r openid", context: {} }),
    );
    expect(result.claims).toEqual({
      tenant: "demo",
      audience: "https://fhir.example.org/fhir",
      issuer: "https://signet.example.org/t/demo/e/pathling",
      client: "client-1",
      client_name: "Test client",
      client_type: "public",
      vendor: "acme",
      grant: "authorization_code",
      subject: "u1",
      roles: ["clinician"],
      department: "Cardiology",
      // `openid` was requested but not granted, so it is not in `granted`.
      scope: "patient/Observation.r",
      endpoint_slug: "pathling",
    });
  });

  it("exposes only granted scopes, never requested ones", () => {
    const result = evaluatePolicy(
      policy({
        scopeGrants: [{ match: "patient/*.r", allow: true }],
        claimRules: [
          { when: { always: true }, emit: { scope: "{{ granted }}" } },
        ],
      }),
      context({ requested: "patient/Observation.r patient/Observation.cud" }),
    );
    expect(result.claims["scope"]).toEqual(["patient/Observation.r"]);
  });
});

/** Evaluates a single always-emitting claim rule and reports whether it fired. */
function fired(
  when: ClaimRule["when"],
  contextOverrides: ContextOverrides = {},
): boolean {
  const result = evaluatePolicy(
    policy({ claimRules: [{ when, emit: { hit: true } }] }),
    context(contextOverrides),
  );
  return result.claims["hit"] === true;
}

/** Evaluates a scope condition against a policy that grants identity scopes. */
function firedWithIdentity(requested: string): boolean {
  const result = evaluatePolicy(
    policy({
      scopeGrants: [
        { match: "openid", allow: true },
        { match: "fhirUser", allow: true },
      ],
      claimRules: [{ when: { scope: "openid" }, emit: { hit: true } }],
    }),
    context({ requested }),
  );
  return result.claims["hit"] === true;
}

describe("evaluatePolicy — conditions", () => {
  it("matches an empty condition", () => {
    expect(fired({})).toBe(true);
  });

  it("treats always: false as never matching", () => {
    expect(fired({ always: false })).toBe(false);
    expect(fired({ always: true })).toBe(true);
  });

  it("requires a granted scope to match the scope condition, using within", () => {
    expect(
      fired({ scope: "patient/*.rs" }, { requested: "patient/Observation.r" }),
    ).toBe(true);
    expect(
      fired({ scope: "patient/Observation.r" }, { requested: "patient/*.r" }),
    ).toBe(false);
    expect(
      fired({ scope: "patient/*.rs" }, { requested: "user/Patient.r" }),
    ).toBe(false);
    expect(fired({ scope: "patient/*.rs" }, {})).toBe(false);
  });

  it("supports a non-resource scope condition by exact equality", () => {
    expect(firedWithIdentity("openid")).toBe(true);
    expect(firedWithIdentity("fhirUser")).toBe(false);
  });

  it("requires every named launch context key", () => {
    expect(
      fired({ context: ["patient"] }, { context: { patient: "P/1" } }),
    ).toBe(true);
    expect(fired({ context: ["patient"] }, { context: {} })).toBe(false);
    expect(
      fired(
        { context: ["patient", "encounter"] },
        { context: { patient: "P/1" } },
      ),
    ).toBe(false);
  });

  it("accepts a boolean launch context key that is false", () => {
    // Presence is what matters: `needPatientBanner: false` was still supplied.
    expect(
      fired(
        { context: ["needPatientBanner"] },
        { context: { needPatientBanner: false } },
      ),
    ).toBe(true);
  });

  it("treats an empty fhirContext array as absent", () => {
    expect(
      fired({ context: ["fhirContext"] }, { context: { fhirContext: [] } }),
    ).toBe(false);
    expect(
      fired(
        { context: ["fhirContext"] },
        { context: { fhirContext: [{ reference: "DiagnosticReport/1" }] } },
      ),
    ).toBe(true);
  });

  it("honours grantTypes and clientTypes", () => {
    expect(fired({ grantTypes: ["client_credentials"] })).toBe(false);
    expect(
      fired(
        { grantTypes: ["client_credentials"] },
        { grantType: "client_credentials" },
      ),
    ).toBe(true);
    expect(fired({ clientTypes: ["public"] })).toBe(true);
    expect(fired({ clientTypes: ["confidential-symmetric"] })).toBe(false);
  });

  it("honours userRole", () => {
    expect(fired({ userRole: ["clinician"] })).toBe(true);
    expect(fired({ userRole: ["admin"] })).toBe(false);
    expect(fired({ userRole: ["clinician"] }, { user: null })).toBe(false);
  });

  it("honours hasUser in both directions", () => {
    expect(fired({ hasUser: true })).toBe(true);
    expect(fired({ hasUser: false })).toBe(false);
    expect(fired({ hasUser: true }, { user: null })).toBe(false);
    expect(fired({ hasUser: false }, { user: null })).toBe(true);
  });

  it("requires every condition to hold at once", () => {
    expect(
      fired(
        {
          hasUser: true,
          userRole: ["clinician"],
          grantTypes: ["authorization_code"],
        },
        {},
      ),
    ).toBe(true);
    expect(
      fired(
        {
          hasUser: true,
          userRole: ["clinician"],
          grantTypes: ["client_credentials"],
        },
        {},
      ),
    ).toBe(false);
  });

  it("drops a user claim when the user has no FHIR resource", () => {
    const result = evaluatePolicy(
      policy({
        claimRules: [
          {
            when: { hasUser: true },
            emit: { fhirUser: "{{ user.fhirUser }}" },
          },
        ],
      }),
      context({ user: { ...USER, fhirUser: null } }),
    );
    expect(result.claims).toEqual({});
  });
});

describe("evaluatePolicy — scope mappings", () => {
  it("appends one value per matching granted scope, deduplicated in order", () => {
    const result = evaluatePolicy(
      policy({
        scopeMappings: [
          {
            forEachScope: "*/*.r",
            appendTo: "authorities",
            values: ["read{{ scope.resourceTypeSuffix }}", "shared"],
          },
        ],
      }),
      context({
        requested:
          "patient/Observation.rs patient/Condition.r patient/Observation.r",
      }),
    );
    expect(result.claims["authorities"]).toEqual([
      "read:Observation",
      "shared",
      "read:Condition",
    ]);
  });

  it("uses intersects matching, not within", () => {
    const result = evaluatePolicy(
      policy({
        scopeMappings: [
          { forEachScope: "*/*.r", appendTo: "authorities", values: ["read"] },
        ],
      }),
      context({ requested: "patient/Observation.cruds" }),
    );
    expect(result.claims["authorities"]).toEqual(["read"]);
  });

  it("ignores scopes that share no permission", () => {
    const result = evaluatePolicy(
      policy({
        scopeMappings: [
          {
            forEachScope: "*/*.cud",
            appendTo: "authorities",
            values: ["write"],
          },
        ],
      }),
      context({ requested: "patient/Observation.rs" }),
    );
    expect(result.claims["authorities"]).toBeUndefined();
  });

  it("leaves the claim absent when nothing matched", () => {
    const result = evaluatePolicy(
      policy({
        scopeMappings: [
          {
            forEachScope: "system/*.r",
            appendTo: "authorities",
            values: ["read"],
          },
        ],
      }),
      context({ requested: "patient/Observation.r" }),
    );
    expect("authorities" in result.claims).toBe(false);
  });

  it("only ever sees granted scopes", () => {
    const result = evaluatePolicy(
      policy({
        scopeGrants: [{ match: "patient/*.rs", allow: true }],
        scopeMappings: [
          {
            forEachScope: "*/*.cruds",
            appendTo: "authorities",
            values: ["touch{{ scope.resourceTypeSuffix }}"],
          },
        ],
      }),
      context({ requested: "patient/Observation.r patient/Condition.cud" }),
    );
    expect(result.claims["authorities"]).toEqual(["touch:Observation"]);
  });

  it("appends after values seeded by a claim rule", () => {
    const result = evaluatePolicy(
      policy({
        claimRules: [
          { when: { always: true }, emit: { authorities: ["seeded", "read"] } },
        ],
        scopeMappings: [
          { forEachScope: "*/*.r", appendTo: "authorities", values: ["read"] },
        ],
      }),
      context({ requested: "patient/Observation.r" }),
    );
    expect(result.claims["authorities"]).toEqual(["seeded", "read"]);
  });

  it("promotes a seeded scalar into the array rather than losing it", () => {
    const result = evaluatePolicy(
      policy({
        claimRules: [
          { when: { always: true }, emit: { authorities: "seeded" } },
        ],
        scopeMappings: [
          { forEachScope: "*/*.r", appendTo: "authorities", values: ["read"] },
        ],
      }),
      context({ requested: "patient/Observation.r" }),
    );
    expect(result.claims["authorities"]).toEqual(["seeded", "read"]);
  });

  it("skips a disabled mapping rule", () => {
    const result = evaluatePolicy(
      policy({
        scopeMappings: [
          {
            enabled: false,
            forEachScope: "*/*.r",
            appendTo: "authorities",
            values: ["read"],
          },
        ],
      }),
      context({ requested: "patient/Observation.r" }),
    );
    expect("authorities" in result.claims).toBe(false);
  });

  it("honours a mapping rule condition", () => {
    const mappings: readonly ScopeMappingRule[] = [
      {
        when: { grantTypes: ["client_credentials"] },
        forEachScope: "*/*.r",
        appendTo: "authorities",
        values: ["read"],
      },
    ];
    expect(
      evaluatePolicy(
        policy({ scopeMappings: mappings }),
        context({ requested: "system/Patient.r" }),
      ).claims["authorities"],
    ).toBeUndefined();
    expect(
      evaluatePolicy(
        policy({ scopeMappings: mappings }),
        context({
          requested: "system/Patient.r",
          grantType: "client_credentials",
        }),
      ).claims["authorities"],
    ).toEqual(["read"]);
  });

  it("exposes every documented scope variable", () => {
    const result = evaluatePolicy(
      policy({
        scopeMappings: [
          {
            forEachScope: "*/*.r",
            appendTo: "detail",
            values: [
              "context={{ scope.context }}",
              "type={{ scope.resourceType }}",
              "permissions={{ scope.permissions | join:, }}",
              "wildcard={{ scope.isWildcard }}",
              "suffix={{ scope.resourceTypeSuffix }}",
              "value={{ scope.value }}",
            ],
          },
        ],
      }),
      context({ requested: "patient/Observation.rs" }),
    );
    expect(result.claims["detail"]).toEqual([
      "context=patient",
      "type=Observation",
      "permissions=r,s",
      "wildcard=false",
      "suffix=:Observation",
      "value=patient/Observation.rs",
    ]);
  });

  it("renders a wildcard scope with an empty resource type suffix", () => {
    const result = evaluatePolicy(
      policy({
        scopeMappings: [
          {
            forEachScope: "*/*.r",
            appendTo: "authorities",
            values: [
              "read{{ scope.resourceTypeSuffix }}",
              "wildcard={{ scope.isWildcard }}",
            ],
          },
        ],
      }),
      context({ requested: "system/*.r", grantType: "client_credentials" }),
    );
    expect(result.claims["authorities"]).toEqual(["read", "wildcard=true"]);
  });

  it("keeps the other template variables available while a scope is bound", () => {
    const result = evaluatePolicy(
      policy({
        scopeMappings: [
          {
            forEachScope: "*/*.r",
            appendTo: "authorities",
            values: ["{{ endpoint.slug }}:{{ scope.resourceType }}"],
          },
        ],
      }),
      context({ requested: "patient/Observation.r" }),
    );
    expect(result.claims["authorities"]).toEqual(["pathling:Observation"]);
  });

  it("drops a value whose template does not resolve", () => {
    const result = evaluatePolicy(
      policy({
        scopeMappings: [
          {
            forEachScope: "*/*.r",
            appendTo: "authorities",
            values: ["read", "{{ scope.nonsense }}", "{{ scope.permissions }}"],
          },
        ],
      }),
      context({ requested: "patient/Observation.rs" }),
    );
    // The array-valued template is flattened into its entries.
    expect(result.claims["authorities"]).toEqual(["read", "r", "s"]);
  });

  it("coerces a non-string mapping value and drops one with no textual form", () => {
    const result = evaluatePolicy(
      policy({
        scopeMappings: [
          {
            forEachScope: "*/*.r",
            appendTo: "authorities",
            values: [
              "{{ scope.isWildcard }}",
              "{{ client.attributes }}",
              "",
              "kept",
            ],
          },
        ],
      }),
      context({ requested: "patient/Observation.r" }),
    );
    expect(result.claims["authorities"]).toEqual(["false", "kept"]);
  });

  it("promotes seeded numbers and booleans, dropping structured entries", () => {
    const result = evaluatePolicy(
      policy({
        claimRules: [
          {
            when: { always: true },
            emit: { authorities: [1, true, null, ["nested"], "kept"] },
          },
        ],
        scopeMappings: [
          { forEachScope: "*/*.r", appendTo: "authorities", values: ["read"] },
        ],
      }),
      context({ requested: "patient/Observation.r" }),
    );
    expect(result.claims["authorities"]).toEqual(["1", "true", "kept", "read"]);
  });

  it("ignores a seeded claim that is not appendable at all", () => {
    const result = evaluatePolicy(
      policy({
        claimRules: [
          { when: { always: true }, emit: { authorities: { a: "1" } } },
        ],
        scopeMappings: [
          { forEachScope: "*/*.r", appendTo: "authorities", values: ["read"] },
        ],
      }),
      context({ requested: "patient/Observation.r" }),
    );
    expect(result.claims["authorities"]).toEqual(["read"]);
  });

  it("can map a non-resource scope matched by exact equality", () => {
    const result = evaluatePolicy(
      policy({
        scopeGrants: [{ match: "openid", allow: true }],
        scopeMappings: [
          {
            forEachScope: "openid",
            appendTo: "authorities",
            values: [
              "identity:{{ scope.value }}",
              "kind={{ scope.kind }}",
              "wildcard={{ scope.isWildcard }}",
              "suffix=[{{ scope.resourceTypeSuffix }}]",
            ],
          },
        ],
      }),
      context({ requested: "openid" }),
    );
    expect(result.claims["authorities"]).toEqual([
      "identity:openid",
      "kind=identity",
      "wildcard=false",
      "suffix=[]",
    ]);
  });

  it("runs several mapping rules into the same claim in order", () => {
    const result = evaluatePolicy(
      policy({
        scopeMappings: [
          { forEachScope: "*/*.r", appendTo: "authorities", values: ["read"] },
          {
            forEachScope: "*/*.s",
            appendTo: "authorities",
            values: ["search"],
          },
        ],
      }),
      context({ requested: "patient/Observation.rs" }),
    );
    expect(result.claims["authorities"]).toEqual(["read", "search"]);
  });
});

describe("evaluatePolicy — context rules", () => {
  it("emits into the token response, not the token", () => {
    const result = evaluatePolicy(
      policy({
        contextRules: [
          {
            when: { context: ["patient"] },
            emit: { patient: "{{ context.patient }}" },
          },
        ],
      }),
      context({ context: { patient: "Patient/123" } }),
    );
    expect(result.contextParams).toEqual({ patient: "Patient/123" });
    expect(result.claims).toEqual({});
  });

  it("treats an absent condition as always matching", () => {
    const result = evaluatePolicy(
      policy({
        contextRules: [{ emit: { smart_style_url: "https://x/style" } }],
      }),
      context(),
    );
    expect(result.contextParams).toEqual({
      smart_style_url: "https://x/style",
    });
  });

  it("lets a later rule overwrite an earlier one", () => {
    const result = evaluatePolicy(
      policy({
        contextRules: [
          { emit: { need_patient_banner: true } },
          { emit: { need_patient_banner: "{{ context.needPatientBanner }}" } },
        ],
      }),
      context({ context: { needPatientBanner: false } }),
    );
    expect(result.contextParams["need_patient_banner"]).toBe(false);
  });

  it("keeps the earlier value when the override does not resolve", () => {
    const result = evaluatePolicy(
      policy({
        contextRules: [
          { emit: { need_patient_banner: true } },
          { emit: { need_patient_banner: "{{ context.needPatientBanner }}" } },
        ],
      }),
      context({ context: {} }),
    );
    expect(result.contextParams["need_patient_banner"]).toBe(true);
  });

  it("skips a disabled rule", () => {
    const result = evaluatePolicy(
      policy({ contextRules: [{ enabled: false, emit: { a: "1" } }] }),
      context(),
    );
    expect(result.contextParams).toEqual({});
  });
});

describe("evaluatePolicy — lifetimes", () => {
  it("returns the configured token lifetimes", () => {
    const result = evaluatePolicy(
      policy({ accessTokenTtl: 900, refreshTokenTtl: 1_209_600 }),
      context(),
    );
    expect(result.accessTokenTtl).toBe(900);
    expect(result.refreshTokenTtl).toBe(1_209_600);
  });
});

describe("evaluatePolicy — purity", () => {
  it("returns the same result for the same inputs", () => {
    const document = policy({
      claimRules: [
        { when: { always: true }, emit: { a: "{{ endpoint.slug }}" } },
      ],
      scopeMappings: [
        { forEachScope: "*/*.r", appendTo: "authorities", values: ["read"] },
      ],
      contextRules: [{ emit: { patient: "{{ context.patient }}" } }],
    });
    const input = context({
      requested: "patient/Observation.rs",
      context: { patient: "Patient/1" },
    });
    expect(evaluatePolicy(document, input)).toEqual(
      evaluatePolicy(document, input),
    );
  });

  it("does not mutate its inputs", () => {
    const document = policy({
      scopeMappings: [
        { forEachScope: "*/*.r", appendTo: "authorities", values: ["read"] },
      ],
    });
    const input = context({ requested: "patient/Observation.rs" });
    const documentBefore = JSON.stringify(document);
    const inputBefore = JSON.stringify(input);
    evaluatePolicy(document, input);
    expect(JSON.stringify(document)).toBe(documentBefore);
    expect(JSON.stringify(input)).toBe(inputBefore);
  });
});
