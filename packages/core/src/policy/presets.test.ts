/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { evaluatePolicy } from "./evaluate.js";
import {
  AIDBOX_PRESET,
  FIRELY_PRESET,
  ONTOSERVER_PRESET,
  PATHLING_PRESET,
  POLICY_PRESETS,
  SMART_BASELINE_PRESET,
  SMILE_CDR_PRESET,
} from "./presets.js";
import { formatScope, parseScopes, PERMISSION_ORDER } from "../scopes/index.js";

import type {
  EvaluationContext,
  EvaluationUser,
  GrantType,
  PolicyDocument,
  ScopeGrantRule,
} from "./types.js";
import type { LaunchContext } from "../launch/types.js";
import type { Permission, Scope } from "../scopes/types.js";

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

const USER: EvaluationUser = {
  id: "u1",
  fhirUser: "Practitioner/abc",
  displayName: "Dr Example",
  roles: ["clinician"],
  attributes: {},
};

/** The parts of an evaluation context a preset test may vary. */
interface ContextOverrides {
  readonly requested?: string;
  readonly context?: LaunchContext;
  readonly user?: EvaluationUser | null;
  readonly grantType?: GrantType;
  readonly clientType?: EvaluationContext["client"]["type"];
}

/** Builds an evaluation context with defaults typical of an EHR launch. */
function context(overrides: ContextOverrides = {}): EvaluationContext {
  return {
    endpoint: {
      tenantSlug: "demo",
      slug: "pathling",
      issuer: "https://signet.example.org/t/demo/e/pathling",
      fhirBaseUrl: "https://pathling.example.org/fhir",
    },
    client: {
      clientId: "client-1",
      name: "Analytics app",
      type: overrides.clientType ?? "public",
      attributes: {},
    },
    user: overrides.user === undefined ? USER : overrides.user,
    requested: scopes(overrides.requested ?? ""),
    context: overrides.context ?? {},
    grantType: overrides.grantType ?? "authorization_code",
  };
}

/** Grants that allow everything, for exercising a mapping table in isolation. */
const ALLOW_ALL_GRANTS: readonly ScopeGrantRule[] = [
  { match: "*/*.cruds", allow: true },
  { match: "openid", allow: true },
  { match: "fhirUser", allow: true },
];

/**
 * The Pathling preset with its grant rules replaced by an allow-everything rule.
 *
 * The mapping table is what this file is really about, and it can only be
 * exercised for scopes that were granted. Separating the two means a change to
 * the preset's grants can never quietly stop the mapping assertions from running.
 */
const PATHLING_MAPPING_HARNESS: PolicyDocument = {
  ...PATHLING_PRESET,
  scopeGrants: ALLOW_ALL_GRANTS,
};

/** A copy of a policy with one disabled grant rule switched on, by id. */
function withGrantEnabled(
  policy: PolicyDocument,
  ruleId: string,
): PolicyDocument {
  return {
    ...policy,
    scopeGrants: policy.scopeGrants.map((rule) =>
      rule.id === ruleId ? { ...rule, enabled: true } : rule,
    ),
  };
}

/** A copy of a policy with one disabled mapping rule switched on, by id. */
function withMappingEnabled(
  policy: PolicyDocument,
  ruleId: string,
): PolicyDocument {
  return {
    ...policy,
    scopeMappings: (policy.scopeMappings ?? []).map((rule) =>
      rule.id === ruleId ? { ...rule, enabled: true } : rule,
    ),
  };
}

/** The authorities a policy's mapping table produces for a scope string. */
function mappedAuthorities(
  policy: PolicyDocument,
  requested: string,
  overrides: ContextOverrides = {},
): readonly string[] {
  const result = evaluatePolicy(policy, context({ ...overrides, requested }));
  const authorities = result.claims["authorities"];
  if (authorities === undefined) {
    return [];
  }
  if (!Array.isArray(authorities)) {
    throw new TypeError("Expected the authorities claim to be an array");
  }
  return authorities as readonly string[];
}

/** The authorities the Pathling mapping produces for a scope string. */
function authoritiesFor(
  requested: string,
  overrides: ContextOverrides = {},
): readonly string[] {
  return mappedAuthorities(PATHLING_MAPPING_HARNESS, requested, overrides);
}

// Every authority Pathling understands. Anything outside this grammar would be
// silently ignored by Pathling, which is indistinguishable from a policy that
// grants nothing at all.
const DATA_AUTHORITY = /^pathling:(?:read|write)(?::[A-Z][A-Za-z]*)?$/;

/** Operation authorities that need a read authority to be usable. */
const READ_OPERATIONS = new Set<string>([
  "pathling:search",
  "pathling:read-resource",
  "pathling:export",
  "pathling:sql-run",
  "pathling:sql-export",
]);

/** Operation authorities that need a write authority to be usable. */
const WRITE_OPERATIONS = new Set<string>([
  "pathling:create",
  "pathling:update",
  "pathling:delete",
  "pathling:batch",
  "pathling:import",
  "pathling:import-pnp",
  "pathling:bulk-submit",
]);

/**
 * Operation authorities usable with a data authority of either kind.
 *
 * Only `pathling:jobs`, which lists the caller's own asynchronous jobs. Jobs are
 * started by read operations and write operations alike, so pairing it with one
 * kind would leave the other unable to see what it started.
 */
const ANY_DATA_OPERATIONS = new Set<string>(["pathling:jobs"]);

/**
 * Every operation authority in Pathling `release/server/3.0.0`.
 *
 * Taken from the `@OperationAccess` annotations in the server source at
 * `378dba82a9`, which the branch's documentation table now matches exactly.
 * Anything outside this grammar would be silently ignored by Pathling, which is
 * indistinguishable from a policy that grants nothing at all.
 */
const OPERATION_AUTHORITIES = new Set<string>([
  ...READ_OPERATIONS,
  ...WRITE_OPERATIONS,
  ...ANY_DATA_OPERATIONS,
]);

/**
 * The write-side operations that can reshape a whole data warehouse.
 *
 * These follow from a create scope, which the preset grants to nobody by
 * default: an operator reaches them either by holding {@link ADMIN_ROLE} or by
 * enabling the disabled backend service grant. The test below proves both halves
 * of that, because a mapping is only as narrow as the grant feeding it.
 */
const BULK_LOAD_OPERATIONS: readonly string[] = [
  "pathling:import",
  "pathling:import-pnp",
  "pathling:bulk-submit",
];

/** The role the preset's write grant requires. */
const ADMIN_ROLE = "pathling-admin";

/** All non-empty permission subsets, in canonical `cruds` order. */
function permissionSubsets(): readonly (readonly Permission[])[] {
  const subsets: (readonly Permission[])[] = [];
  for (let mask = 1; mask < 1 << PERMISSION_ORDER.length; mask += 1) {
    const subset: Permission[] = [];
    for (const [index, permission] of PERMISSION_ORDER.entries()) {
      if ((mask & (1 << index)) !== 0) {
        subset.push(permission);
      }
    }
    subsets.push(subset);
  }
  return subsets;
}

/**
 * The authority set a scope should map to, derived independently from the rules
 * as documented rather than from the preset's structure.
 *
 * Deliberately written as a second statement of the mapping table. It is only
 * worth having because it is not the implementation: if it were derived from the
 * rules it would agree with them however wrong they both were.
 */
function expectedAuthorities(
  resourceType: string,
  permissions: readonly Permission[],
): readonly string[] {
  const suffix = resourceType === "*" ? "" : `:${resourceType}`;
  const has = (permission: Permission): boolean =>
    permissions.includes(permission);
  const writes = has("c") || has("u") || has("d");
  const expected: string[] = [];

  if (has("r") || has("s")) {
    expected.push(`pathling:read${suffix}`);
  }
  if (has("s")) {
    expected.push("pathling:search");
  }
  if (has("r")) {
    expected.push(
      "pathling:read-resource",
      "pathling:export",
      "pathling:sql-run",
      "pathling:sql-export",
    );
  }
  expected.push("pathling:jobs");
  if (writes) {
    expected.push(`pathling:write${suffix}`);
  }
  if (has("c")) {
    expected.push("pathling:create");
  }
  if (has("u")) {
    expected.push("pathling:update");
  }
  if (has("d")) {
    expected.push("pathling:delete");
  }
  if (writes) {
    expected.push("pathling:batch");
  }
  if (has("c")) {
    expected.push(
      "pathling:import",
      "pathling:import-pnp",
      "pathling:bulk-submit",
    );
  }
  return expected;
}

/**
 * The operation authorities a read permission yields, in emission order.
 *
 * Spelled out once and reused, because writing all four into every row of the
 * table below would bury the part of each row that actually varies.
 */
const READ_DERIVED: readonly string[] = [
  "pathling:read-resource",
  "pathling:export",
  "pathling:sql-run",
  "pathling:sql-export",
];

describe("PATHLING_PRESET - the two mandated cases", () => {
  it("maps patient/Observation.rs to a typed read plus the read operations", () => {
    expect(authoritiesFor("patient/Observation.rs")).toEqual([
      "pathling:read:Observation",
      "pathling:search",
      ...READ_DERIVED,
      "pathling:jobs",
    ]);
  });

  it("maps system/*.rs to an all-types read plus the read operations", () => {
    expect(
      authoritiesFor("system/*.rs", { grantType: "client_credentials" }),
    ).toEqual([
      "pathling:read",
      "pathling:search",
      ...READ_DERIVED,
      "pathling:jobs",
    ]);
  });
});

describe("PATHLING_PRESET - authority table", () => {
  it.each([
    [
      "patient/Observation.r",
      ["pathling:read:Observation", ...READ_DERIVED, "pathling:jobs"],
    ],
    // Search yields no read-by-id, export or SQL authority: those follow from
    // `r`, and a search-only scope has not asked for them.
    [
      "patient/Observation.s",
      ["pathling:read:Observation", "pathling:search", "pathling:jobs"],
    ],
    ["patient/*.r", ["pathling:read", ...READ_DERIVED, "pathling:jobs"]],
    [
      "user/Patient.r",
      ["pathling:read:Patient", ...READ_DERIVED, "pathling:jobs"],
    ],
    ["system/*.s", ["pathling:read", "pathling:search", "pathling:jobs"]],
    [
      "patient/Observation.c",
      [
        "pathling:jobs",
        "pathling:write:Observation",
        "pathling:create",
        "pathling:batch",
        "pathling:import",
        "pathling:import-pnp",
        "pathling:bulk-submit",
      ],
    ],
    [
      "patient/Observation.u",
      [
        "pathling:jobs",
        "pathling:write:Observation",
        "pathling:update",
        "pathling:batch",
      ],
    ],
    [
      "patient/Observation.d",
      [
        "pathling:jobs",
        "pathling:write:Observation",
        "pathling:delete",
        "pathling:batch",
      ],
    ],
    // Create and update are separate authorities in 3.0.0, so a `cu` scope
    // yields both rather than the single `pathling:update` of earlier versions.
    [
      "patient/Observation.cu",
      [
        "pathling:jobs",
        "pathling:write:Observation",
        "pathling:create",
        "pathling:update",
        "pathling:batch",
        "pathling:import",
        "pathling:import-pnp",
        "pathling:bulk-submit",
      ],
    ],
    [
      "user/Patient.cruds",
      [
        "pathling:read:Patient",
        "pathling:search",
        ...READ_DERIVED,
        "pathling:jobs",
        "pathling:write:Patient",
        "pathling:create",
        "pathling:update",
        "pathling:delete",
        "pathling:batch",
        "pathling:import",
        "pathling:import-pnp",
        "pathling:bulk-submit",
      ],
    ],
    // A v1 scope is normalised before mapping, so it behaves as its v2 form.
    [
      "patient/Observation.read",
      [
        "pathling:read:Observation",
        "pathling:search",
        ...READ_DERIVED,
        "pathling:jobs",
      ],
    ],
    [
      "patient/Observation.write",
      [
        "pathling:jobs",
        "pathling:write:Observation",
        "pathling:create",
        "pathling:update",
        "pathling:delete",
        "pathling:batch",
        "pathling:import",
        "pathling:import-pnp",
        "pathling:bulk-submit",
      ],
    ],
  ])("maps %s to %j", (requested, expected) => {
    expect(
      authoritiesFor(requested, { grantType: "client_credentials" }),
    ).toEqual(expected);
  });

  it("accumulates authorities across several scopes without duplicating them", () => {
    expect(
      authoritiesFor(
        "patient/Observation.rs patient/Condition.rs patient/Observation.cud",
      ),
    ).toEqual([
      "pathling:read:Observation",
      "pathling:read:Condition",
      "pathling:search",
      ...READ_DERIVED,
      "pathling:jobs",
      "pathling:write:Observation",
      "pathling:create",
      "pathling:update",
      "pathling:delete",
      "pathling:batch",
      "pathling:import",
      "pathling:import-pnp",
      "pathling:bulk-submit",
    ]);
  });

  it("emits a bare read authority alongside a typed one when both were asked for", () => {
    expect(authoritiesFor("patient/*.r patient/Observation.r")).toEqual([
      "pathling:read",
      "pathling:read:Observation",
      ...READ_DERIVED,
      "pathling:jobs",
    ]);
  });

  it("emits nothing for scopes with no resource access", () => {
    expect(authoritiesFor("openid fhirUser")).toEqual([]);
  });
});

describe("PATHLING_PRESET - invariants across every scope shape", () => {
  const cases = [
    ...(["patient", "user", "system"] as const).flatMap((scopeContext) =>
      ["*", "Observation"].flatMap((resourceType) =>
        permissionSubsets().map(
          (permissions) => [scopeContext, resourceType, permissions] as const,
        ),
      ),
    ),
  ];

  it.each(cases)(
    "maps %s/%s.%s exactly as documented",
    (scopeContext, resourceType, permissions) => {
      const requested = `${scopeContext}/${resourceType}.${permissions.join("")}`;
      expect(
        authoritiesFor(requested, { grantType: "client_credentials" }),
      ).toEqual(expectedAuthorities(resourceType, permissions));
    },
  );

  it.each(cases)(
    "never emits an operation authority without its data authority for %s/%s.%s",
    (scopeContext, resourceType, permissions) => {
      const requested = `${scopeContext}/${resourceType}.${permissions.join("")}`;
      const authorities = authoritiesFor(requested, {
        grantType: "client_credentials",
      });
      const hasRead = authorities.some((authority) =>
        authority.startsWith("pathling:read"),
      );
      const hasWrite = authorities.some((authority) =>
        authority.startsWith("pathling:write"),
      );

      for (const operation of authorities.filter((authority) =>
        READ_OPERATIONS.has(authority),
      )) {
        expect(hasRead, `${operation} without a read authority`).toBe(true);
      }
      for (const operation of authorities.filter((authority) =>
        WRITE_OPERATIONS.has(authority),
      )) {
        expect(hasWrite, `${operation} without a write authority`).toBe(true);
      }
      for (const operation of authorities.filter((authority) =>
        ANY_DATA_OPERATIONS.has(authority),
      )) {
        expect(
          hasRead || hasWrite,
          `${operation} without any data authority`,
        ).toBe(true);
      }
    },
  );

  it.each(cases)(
    "emits only well formed, unique authorities for %s/%s.%s",
    (scopeContext, resourceType, permissions) => {
      const requested = `${scopeContext}/${resourceType}.${permissions.join("")}`;
      const authorities = authoritiesFor(requested, {
        grantType: "client_credentials",
      });
      expect(new Set(authorities).size).toBe(authorities.length);
      for (const authority of authorities) {
        expect(
          DATA_AUTHORITY.test(authority) ||
            OPERATION_AUTHORITIES.has(authority),
          `${authority} is not a Pathling authority`,
        ).toBe(true);
      }
    },
  );

  it.each(cases)(
    "ties bulk loading to a create permission for %s/%s.%s",
    (scopeContext, resourceType, permissions) => {
      const requested = `${scopeContext}/${resourceType}.${permissions.join("")}`;
      const authorities = authoritiesFor(requested, {
        grantType: "client_credentials",
      });
      // Import, ping-and-pull import and bulk submit all write whole resource
      // types at once. Nothing short of an explicit create permission may reach
      // them, and a scope that only reads, updates or deletes never does.
      for (const operation of BULK_LOAD_OPERATIONS) {
        expect(
          authorities.includes(operation),
          `${operation} for ${requested}`,
        ).toBe(permissions.includes("c"));
      }
    },
  );

  it("always pairs search with read, since search alone cannot serve a request", () => {
    for (const [scopeContext, resourceType, permissions] of cases) {
      if (!permissions.includes("s")) {
        continue;
      }
      const authorities = authoritiesFor(
        `${scopeContext}/${resourceType}.${permissions.join("")}`,
        { grantType: "client_credentials" },
      );
      expect(authorities).toContain("pathling:search");
      expect(
        authorities.some((authority) => authority.startsWith("pathling:read")),
      ).toBe(true);
    }
  });

  it("always pairs a write authority with an operation that can use it", () => {
    for (const [scopeContext, resourceType, permissions] of cases) {
      const writes = permissions.filter((permission) =>
        ["c", "u", "d"].includes(permission),
      );
      if (writes.length === 0) {
        continue;
      }
      const authorities = authoritiesFor(
        `${scopeContext}/${resourceType}.${permissions.join("")}`,
        { grantType: "client_credentials" },
      );
      expect(
        authorities.some((authority) => authority.startsWith("pathling:write")),
      ).toBe(true);
      expect(
        authorities.some((authority) => WRITE_OPERATIONS.has(authority)),
      ).toBe(true);
    }
  });

  it("ties every read operation to a read permission, in any context", () => {
    // Export and the projection operations follow from `r` regardless of
    // context, because Pathling's authorities carry no compartment: a
    // patient-context read authority already reads the whole resource type.
    for (const [scopeContext, resourceType, permissions] of cases) {
      const authorities = authoritiesFor(
        `${scopeContext}/${resourceType}.${permissions.join("")}`,
        { grantType: "client_credentials" },
      );
      for (const operation of READ_DERIVED) {
        expect(
          authorities.includes(operation),
          `${operation} for ${scopeContext}/${resourceType}`,
        ).toBe(permissions.includes("r"));
      }
    }
  });

  it("emits the jobs authority for any resource scope, read or write", () => {
    // A job can be started by an export or by an import, so tying `jobs` to one
    // side would leave the other unable to list what it started.
    for (const [scopeContext, resourceType, permissions] of cases) {
      expect(
        authoritiesFor(
          `${scopeContext}/${resourceType}.${permissions.join("")}`,
          { grantType: "client_credentials" },
        ),
      ).toContain("pathling:jobs");
    }
  });

  it("reads a resource by id via read-resource, without widening the data authority", () => {
    // Pathling's read interaction demands the `pathling:read-resource` operation
    // authority (aehrc/pathling#2702) plus the data authority for the type. The
    // preset emits the operation authority from `r`, and must never emit the
    // bare `pathling:read` for a typed scope - that would grant read across
    // every resource type, defeating the narrowing.
    const authorities = authoritiesFor("patient/Observation.rs");
    expect(authorities).toContain("pathling:read:Observation");
    expect(authorities).toContain("pathling:read-resource");
    expect(authorities).not.toContain("pathling:read");
  });
});

describe("PATHLING_PRESET - as shipped", () => {
  it("grants patient reads only once a patient is in context", () => {
    const requested = "patient/Observation.rs";
    expect(
      evaluatePolicy(PATHLING_PRESET, context({ requested })).grantedScopes,
    ).toEqual([]);
    const withPatient = evaluatePolicy(
      PATHLING_PRESET,
      context({ requested, context: { patient: "Patient/123" } }),
    );
    expect(withPatient.grantedScopes.map(formatScope)).toEqual([requested]);
    expect(withPatient.claims["authorities"]).toEqual([
      "pathling:read:Observation",
      "pathling:search",
      ...READ_DERIVED,
      "pathling:jobs",
    ]);
  });

  it("grants system reads only to a client credentials grant", () => {
    const requested = "system/*.rs";
    expect(
      evaluatePolicy(PATHLING_PRESET, context({ requested })).grantedScopes,
    ).toEqual([]);
    const backend = evaluatePolicy(
      PATHLING_PRESET,
      context({ requested, grantType: "client_credentials", user: null }),
    );
    expect(backend.claims["authorities"]).toEqual([
      "pathling:read",
      "pathling:search",
      ...READ_DERIVED,
      "pathling:jobs",
    ]);
  });

  it("denies a backend write, because the system write grant ships disabled", () => {
    const result = evaluatePolicy(
      PATHLING_PRESET,
      context({
        requested: "system/Patient.cud",
        grantType: "client_credentials",
        user: null,
      }),
    );
    expect(result.grantedScopes).toEqual([]);
    expect(result.deniedScopes[0]?.reason).toContain("default is to deny");
    expect(result.claims["authorities"]).toBeUndefined();
  });

  it("lets a backend service write once that grant is enabled", () => {
    // The other half of the disabled rule. Asserting only that it refuses while
    // off would pass just as well against a rule that is broken when on, and the
    // unattended loader is the whole reason the rule is kept.
    const enabled = withGrantEnabled(PATHLING_PRESET, "grant-system-write");
    const result = evaluatePolicy(
      enabled,
      context({
        requested: "system/Patient.cud",
        grantType: "client_credentials",
        user: null,
      }),
    );
    expect(result.grantedScopes.map(formatScope)).toEqual([
      "system/Patient.cud",
    ]);
    // No user, so no role: the loader reaches bulk import through its scope
    // alone, and is still confined to the resource type it named.
    expect(result.claims["authorities"]).toEqual([
      "pathling:jobs",
      "pathling:write:Patient",
      "pathling:create",
      "pathling:update",
      "pathling:delete",
      "pathling:batch",
      "pathling:import",
      "pathling:import-pnp",
      "pathling:bulk-submit",
    ]);
  });

  it("denies a write to a user who does not hold the admin role", () => {
    const result = evaluatePolicy(
      PATHLING_PRESET,
      context({ requested: "user/Patient.cud" }),
    );
    expect(result.grantedScopes).toEqual([]);
    expect(result.deniedScopes[0]?.reason).toContain("default is to deny");
    expect(result.claims["authorities"]).toBeUndefined();
  });

  it("narrows an ordinary user's full request down to reads", () => {
    // The admin grant is the only rule naming a write, so a non-admin asking for
    // everything degrades to read rather than being refused outright.
    const result = evaluatePolicy(
      PATHLING_PRESET,
      context({ requested: "user/Patient.cruds" }),
    );
    expect(result.grantedScopes.map(formatScope)).toEqual(["user/Patient.rs"]);
    expect(result.claims["authorities"]).toEqual([
      "pathling:read:Patient",
      "pathling:search",
      ...READ_DERIVED,
      "pathling:jobs",
    ]);
  });

  it("grants writes and bulk loading to a user holding the admin role", () => {
    const result = evaluatePolicy(
      PATHLING_PRESET,
      context({
        requested: "user/Patient.cruds",
        user: { ...USER, roles: [ADMIN_ROLE] },
      }),
    );
    expect(result.grantedScopes.map(formatScope)).toEqual([
      "user/Patient.cruds",
    ]);
    expect(result.claims["authorities"]).toEqual([
      "pathling:read:Patient",
      "pathling:search",
      ...READ_DERIVED,
      "pathling:jobs",
      "pathling:write:Patient",
      "pathling:create",
      "pathling:update",
      "pathling:delete",
      "pathling:batch",
      "pathling:import",
      "pathling:import-pnp",
      "pathling:bulk-submit",
    ]);
  });

  it("confines the admin grant to the resource types the app asked for", () => {
    // The role decides whether writing is possible at all; the scope still
    // decides what may be written.
    const result = evaluatePolicy(
      PATHLING_PRESET,
      context({
        requested: "user/Patient.cud",
        user: { ...USER, roles: [ADMIN_ROLE] },
      }),
    );
    expect(result.claims["authorities"]).toContain("pathling:write:Patient");
    expect(result.claims["authorities"]).not.toContain("pathling:write");
  });

  it("does not let the admin role reach the system context", () => {
    // System scopes belong to the client credentials grant, where there is no
    // user and so no role. Only the disabled backend grant opens that path.
    const result = evaluatePolicy(
      PATHLING_PRESET,
      context({
        requested: "system/Patient.cud",
        grantType: "client_credentials",
        user: null,
      }),
    );
    expect(result.grantedScopes).toEqual([]);
  });

  it("grants refresh tokens only to a confidential client", () => {
    expect(
      evaluatePolicy(PATHLING_PRESET, context({ requested: "offline_access" }))
        .grantedScopes,
    ).toEqual([]);
    expect(
      evaluatePolicy(
        PATHLING_PRESET,
        context({
          requested: "offline_access",
          clientType: "confidential-asymmetric",
        }),
      ).grantedScopes.map(formatScope),
    ).toEqual(["offline_access"]);
  });

  it("emits the launch context as token response parameters", () => {
    const result = evaluatePolicy(
      PATHLING_PRESET,
      context({
        requested: "openid fhirUser launch patient/Observation.rs",
        context: {
          patient: "Patient/123",
          encounter: "Encounter/456",
          smartStyleUrl: "https://ehr.example.org/style.json",
          intent: "reconcile-medications",
          tenant: "demo",
          fhirContext: [{ reference: "DiagnosticReport/1" }],
        },
      }),
    );
    expect(result.contextParams).toEqual({
      patient: "Patient/123",
      encounter: "Encounter/456",
      need_patient_banner: true,
      smart_style_url: "https://ehr.example.org/style.json",
      intent: "reconcile-medications",
      tenant: "demo",
      fhirContext: [{ reference: "DiagnosticReport/1" }],
    });
  });

  it("emits the fhirUser claim only when a user is present", () => {
    expect(
      evaluatePolicy(PATHLING_PRESET, context({ requested: "openid" })).claims,
    ).toEqual({ fhirUser: "Practitioner/abc" });
    expect(
      evaluatePolicy(
        PATHLING_PRESET,
        context({ grantType: "client_credentials", user: null }),
      ).claims,
    ).toEqual({});
  });

  it("returns the configured token lifetimes", () => {
    const result = evaluatePolicy(PATHLING_PRESET, context());
    expect(result.accessTokenTtl).toBe(3600);
    expect(result.refreshTokenTtl).toBe(2_592_000);
  });
});

describe("SMART_BASELINE_PRESET", () => {
  it("grants reads across all three contexts", () => {
    expect(
      evaluatePolicy(
        SMART_BASELINE_PRESET,
        context({
          requested: "patient/Observation.rs user/Practitioner.r",
          context: { patient: "Patient/123" },
        }),
      ).grantedScopes.map(formatScope),
    ).toEqual(["patient/Observation.rs", "user/Practitioner.r"]);
    expect(
      evaluatePolicy(
        SMART_BASELINE_PRESET,
        context({
          requested: "system/Patient.rs",
          grantType: "client_credentials",
          user: null,
        }),
      ).grantedScopes.map(formatScope),
    ).toEqual(["system/Patient.rs"]);
  });

  it("is read-only: a purely write scope is denied outright", () => {
    const result = evaluatePolicy(
      SMART_BASELINE_PRESET,
      context({
        requested: "patient/Observation.c user/Patient.u system/Patient.d",
        context: { patient: "Patient/123" },
        grantType: "client_credentials",
      }),
    );
    expect(result.grantedScopes).toEqual([]);
    expect(result.deniedScopes).toHaveLength(3);
  });

  it("is read-only: a mixed scope narrows to its read half instead of being refused", () => {
    // Denying outright would leave an app that asked for `.cruds` with no data
    // access at all. Narrowing keeps the policy read-only while letting the app
    // work, which is what the spec's "may grant narrower scopes" is for.
    const result = evaluatePolicy(
      SMART_BASELINE_PRESET,
      context({
        requested: "patient/Observation.cruds",
        context: { patient: "Patient/123" },
      }),
    );
    expect(result.grantedScopes.map(formatScope)).toEqual([
      "patient/Observation.rs",
    ]);
    expect(result.deniedScopes).toEqual([]);
    expect(result.narrowedScopes).toHaveLength(1);
  });

  it("grants the identity and launch scopes an app needs", () => {
    expect(
      evaluatePolicy(
        SMART_BASELINE_PRESET,
        context({
          requested:
            "openid fhirUser launch launch/patient launch/encounter online_access",
        }),
      ).grantedScopes.map(formatScope),
    ).toEqual([
      "openid",
      "fhirUser",
      "launch",
      "launch/patient",
      "launch/encounter",
      "online_access",
    ]);
  });

  it("emits the patient, encounter and banner context parameters", () => {
    const result = evaluatePolicy(
      SMART_BASELINE_PRESET,
      context({
        requested: "openid",
        context: { patient: "Patient/123", encounter: "Encounter/456" },
      }),
    );
    expect(result.contextParams).toEqual({
      patient: "Patient/123",
      encounter: "Encounter/456",
      need_patient_banner: true,
    });
  });

  it("lets the launch override the banner requirement, keeping it a boolean", () => {
    const result = evaluatePolicy(
      SMART_BASELINE_PRESET,
      context({
        context: { patient: "Patient/123", needPatientBanner: false },
      }),
    );
    expect(result.contextParams["need_patient_banner"]).toBe(false);
  });

  it("emits no banner parameter when there is no patient and no instruction", () => {
    const result = evaluatePolicy(SMART_BASELINE_PRESET, context());
    expect("need_patient_banner" in result.contextParams).toBe(false);
  });

  it("emits the fhirUser claim and nothing else", () => {
    expect(
      evaluatePolicy(SMART_BASELINE_PRESET, context({ requested: "openid" }))
        .claims,
    ).toEqual({ fhirUser: "Practitioner/abc" });
  });

  it("has no scope mappings, since the FHIR server reads SMART scopes itself", () => {
    expect(SMART_BASELINE_PRESET.scopeMappings).toBeUndefined();
  });
});

describe("AIDBOX_PRESET", () => {
  it("declares the access token version, with or without a patient", () => {
    expect(
      evaluatePolicy(AIDBOX_PRESET, context({ requested: "openid" })).claims[
        "atv"
      ],
    ).toBe(2);
    expect(
      evaluatePolicy(
        AIDBOX_PRESET,
        context({ requested: "openid", context: { patient: "123" } }),
      ).claims["atv"],
    ).toBe(2);
  });

  it("nests the patient under a context claim, as Aidbox reads it", () => {
    const result = evaluatePolicy(
      AIDBOX_PRESET,
      context({ requested: "openid", context: { patient: "123" } }),
    );
    expect(result.claims["context"]).toEqual({ patient: "123" });
    // Not at the top level: an Aidbox that found `patient` there would ignore it,
    // and emitting both would suggest a contract that does not exist.
    expect("patient" in result.claims).toBe(false);
  });

  it("emits no context claim at all when no patient was resolved", () => {
    const result = evaluatePolicy(
      AIDBOX_PRESET,
      context({ requested: "user/Observation.rs" }),
    );
    expect("context" in result.claims).toBe(false);
  });

  it("still passes the patient in the token response, per SMART", () => {
    const result = evaluatePolicy(
      AIDBOX_PRESET,
      context({ requested: "openid", context: { patient: "123" } }),
    );
    expect(result.contextParams["patient"]).toBe("123");
  });
});

describe.each([
  ["FIRELY_PRESET", FIRELY_PRESET],
  ["SMILE_CDR_PRESET", SMILE_CDR_PRESET],
] as const)("%s", (_name, preset) => {
  it("emits the patient as a claim inside the token", () => {
    const result = evaluatePolicy(
      preset,
      context({ requested: "openid", context: { patient: "123" } }),
    );
    expect(result.claims["patient"]).toBe("123");
    expect(result.claims["fhirUser"]).toBe("Practitioner/abc");
  });

  it("omits the patient claim when no patient was resolved", () => {
    const result = evaluatePolicy(
      preset,
      context({ requested: "user/Observation.rs" }),
    );
    // An empty compartment claim is worse than none: a server matching against it
    // may filter on nothing at all.
    expect("patient" in result.claims).toBe(false);
  });

  it("keeps the baseline's grants and context parameters", () => {
    expect(preset.scopeGrants).toBe(SMART_BASELINE_PRESET.scopeGrants);
    expect(preset.contextRules).toBe(SMART_BASELINE_PRESET.contextRules);
    expect(preset.scopeMappings).toBeUndefined();
  });
});

/**
 * The Ontoserver preset with its grant rules replaced by an allow-everything
 * rule, for the same reason as the Pathling harness above: the mapping table can
 * only be exercised for scopes that were granted, and keeping the two apart
 * means a grant change can never quietly silence the mapping assertions.
 */
const ONTOSERVER_MAPPING_HARNESS: PolicyDocument = {
  ...ONTOSERVER_PRESET,
  scopeGrants: ALLOW_ALL_GRANTS,
};

/** The role the Ontoserver preset's write grant requires. */
const ONTOSERVER_ADMIN_ROLE = "ontoserver-admin";

describe("ONTOSERVER_PRESET - authority mapping", () => {
  // Ontoserver reads no SMART v2 scopes: it authorises off v1-style authority
  // strings, merged from the token's `scope` and `authorities` claims. The
  // mapping table below is therefore the whole point of the preset - a granted
  // scope becomes one of the exact strings Ontoserver's documentation names.
  // That documented set is server-wide: there is no per-resource-type or
  // per-compartment string to emit, so every read scope becomes `system/*.read`
  // and every write scope becomes `system/*.write`, whatever the scope named.
  it.each([
    ["user/ValueSet.rs", ["system/*.read"]],
    // Search alone still yields the read authority: Ontoserver has no separate
    // search permission, and a search returns the resources it matched.
    ["user/ValueSet.s", ["system/*.read"]],
    ["user/*.rs", ["system/*.read"]],
    ["system/*.rs", ["system/*.read"]],
    ["user/CodeSystem.cruds", ["system/*.read", "system/*.write"]],
    // Ontoserver documents that a write permission does not convey read, and
    // the mapping preserves that: no read authority follows from `cud`.
    ["user/ValueSet.cud", ["system/*.write"]],
    ["system/*.cud", ["system/*.write"]],
    // A v1 scope is normalised before mapping, so it behaves as its v2 form.
    ["user/ConceptMap.read", ["system/*.read"]],
  ])("maps %s to %j", (requested, expected) => {
    expect(
      mappedAuthorities(ONTOSERVER_MAPPING_HARNESS, requested, {
        grantType: "client_credentials",
      }),
    ).toEqual(expected);
  });

  it("deduplicates the wildcard authorities across several scopes", () => {
    expect(
      mappedAuthorities(
        ONTOSERVER_MAPPING_HARNESS,
        "user/ValueSet.rs user/CodeSystem.rs user/CodeSystem.cud",
      ),
    ).toEqual(["system/*.read", "system/*.write"]);
  });

  it("emits no authorities claim for scopes with no resource access", () => {
    expect(
      mappedAuthorities(ONTOSERVER_MAPPING_HARNESS, "openid fhirUser"),
    ).toEqual([]);
  });
});

describe("ONTOSERVER_PRESET - optional rules", () => {
  it("emits the external upload authority only for a create scope naming CodeSystem, once enabled", () => {
    const harness = withMappingEnabled(
      ONTOSERVER_MAPPING_HARNESS,
      "ontoserver-upload-external",
    );
    // The upload gate is deliberately outside `system/*.write` on Ontoserver's
    // side, so the preset keeps it a separate, disabled rule.
    expect(mappedAuthorities(harness, "user/CodeSystem.c")).toEqual([
      "system/*.write",
      "system/CodeSystem.x-upload-external",
    ]);
    // A wildcard scope asks for more than the pattern names, so the upload
    // authority follows only from a scope naming CodeSystem itself. This is
    // Ontoserver's own fence: upload sits outside system/*.write on purpose.
    expect(mappedAuthorities(harness, "user/*.c")).toEqual(["system/*.write"]);
    expect(mappedAuthorities(harness, "user/ValueSet.c")).toEqual([
      "system/*.write",
    ]);
  });

  it("emits the syndication write authority for update and delete scopes, once enabled", () => {
    const harness = withMappingEnabled(
      ONTOSERVER_MAPPING_HARNESS,
      "ontoserver-synd-write",
    );
    expect(mappedAuthorities(harness, "user/ValueSet.u")).toEqual([
      "system/*.write",
      "onto/synd.write",
    ]);
    expect(mappedAuthorities(harness, "user/ValueSet.d")).toEqual([
      "system/*.write",
      "onto/synd.write",
    ]);
    // A create cannot overwrite syndicated content, so a create-only scope
    // does not carry the authority.
    expect(mappedAuthorities(harness, "user/ValueSet.c")).toEqual([
      "system/*.write",
    ]);
  });

  it("emits neither optional authority while the rules ship disabled", () => {
    const authorities = mappedAuthorities(
      ONTOSERVER_MAPPING_HARNESS,
      "user/CodeSystem.cruds",
    );
    expect(authorities).not.toContain("system/CodeSystem.x-upload-external");
    expect(authorities).not.toContain("onto/synd.write");
  });
});

describe("ONTOSERVER_PRESET - as shipped", () => {
  it("refuses patient scopes even when a patient is in context", () => {
    // A terminology server holds no patient data, and an emitted authority
    // carries no compartment - so granting a patient scope would hand the app
    // server-wide read under a name that promises less.
    const result = evaluatePolicy(
      ONTOSERVER_PRESET,
      context({
        requested: "patient/ValueSet.rs",
        context: { patient: "Patient/123" },
      }),
    );
    expect(result.grantedScopes).toEqual([]);
    expect(result.deniedScopes[0]?.reason).toContain("default is to deny");
  });

  it("refuses the patient and encounter launch-context scopes", () => {
    // Dropped for the same reason as the patient grants: there is no patient
    // context for a terminology server to resolve.
    const result = evaluatePolicy(
      ONTOSERVER_PRESET,
      context({ requested: "launch launch/patient launch/encounter" }),
    );
    expect(result.grantedScopes.map(formatScope)).toEqual(["launch"]);
  });

  it("narrows an ordinary user's full request down to reads", () => {
    const result = evaluatePolicy(
      ONTOSERVER_PRESET,
      context({ requested: "user/ValueSet.cruds" }),
    );
    expect(result.grantedScopes.map(formatScope)).toEqual(["user/ValueSet.rs"]);
    expect(result.claims["authorities"]).toEqual(["system/*.read"]);
    expect(result.claims["fhirUser"]).toBe("Practitioner/abc");
  });

  it("grants writes to a user holding the admin role", () => {
    const result = evaluatePolicy(
      ONTOSERVER_PRESET,
      context({
        requested: "user/CodeSystem.cruds",
        user: { ...USER, roles: [ONTOSERVER_ADMIN_ROLE] },
      }),
    );
    expect(result.grantedScopes.map(formatScope)).toEqual([
      "user/CodeSystem.cruds",
    ]);
    expect(result.claims["authorities"]).toEqual([
      "system/*.read",
      "system/*.write",
    ]);
  });

  it("grants system reads only to a client credentials grant", () => {
    expect(
      evaluatePolicy(ONTOSERVER_PRESET, context({ requested: "system/*.rs" }))
        .grantedScopes,
    ).toEqual([]);
    const backend = evaluatePolicy(
      ONTOSERVER_PRESET,
      context({
        requested: "system/*.rs",
        grantType: "client_credentials",
        user: null,
      }),
    );
    expect(backend.grantedScopes.map(formatScope)).toEqual(["system/*.rs"]);
    expect(backend.claims["authorities"]).toEqual(["system/*.read"]);
  });

  it("denies a backend write until the disabled grant is enabled", () => {
    // Both halves, because a rule that refuses while off would pass just as
    // well if it were broken while on.
    const backendWrite = {
      requested: "system/CodeSystem.cud",
      grantType: "client_credentials" as const,
      user: null,
    };
    const denied = evaluatePolicy(ONTOSERVER_PRESET, context(backendWrite));
    expect(denied.grantedScopes).toEqual([]);
    expect(denied.claims["authorities"]).toBeUndefined();
    const granted = evaluatePolicy(
      withGrantEnabled(ONTOSERVER_PRESET, "grant-system-write"),
      context(backendWrite),
    );
    expect(granted.grantedScopes.map(formatScope)).toEqual([
      "system/CodeSystem.cud",
    ]);
    expect(granted.claims["authorities"]).toEqual(["system/*.write"]);
  });

  it("passes no patient context to the app, even when the launch carried one", () => {
    // The grants refuse every patient-facing scope, and the context parameters
    // follow: a terminology server launch has no patient to pass and no banner
    // to show. The parameters that stay meaningful still flow.
    const result = evaluatePolicy(
      ONTOSERVER_PRESET,
      context({
        requested: "openid",
        context: {
          patient: "Patient/123",
          encounter: "Encounter/456",
          needPatientBanner: true,
          smartStyleUrl: "https://ehr.example.org/style.json",
          intent: "browse-terminology",
          tenant: "demo",
        },
      }),
    );
    expect(result.contextParams).toEqual({
      smart_style_url: "https://ehr.example.org/style.json",
      intent: "browse-terminology",
      tenant: "demo",
    });
  });

  it("returns the configured token lifetimes", () => {
    const result = evaluatePolicy(ONTOSERVER_PRESET, context());
    expect(result.accessTokenTtl).toBe(3600);
    expect(result.refreshTokenTtl).toBe(2_592_000);
  });
});

describe("POLICY_PRESETS", () => {
  it("lists every preset with unique ids and non-empty descriptions", () => {
    expect(POLICY_PRESETS.map((preset) => preset.id)).toEqual([
      "smart-baseline",
      "pathling",
      "aidbox",
      "firely",
      "smile-cdr",
      "ontoserver",
    ]);
    expect(new Set(POLICY_PRESETS.map((preset) => preset.id)).size).toBe(
      POLICY_PRESETS.length,
    );
    for (const preset of POLICY_PRESETS) {
      expect(preset.name.length).toBeGreaterThan(0);
      expect(preset.description.length).toBeGreaterThan(0);
      expect(preset.policy.version).toBe(1);
    }
  });

  it("points at the exported documents", () => {
    expect(POLICY_PRESETS[0]?.policy).toBe(SMART_BASELINE_PRESET);
    expect(POLICY_PRESETS[1]?.policy).toBe(PATHLING_PRESET);
    expect(POLICY_PRESETS[2]?.policy).toBe(AIDBOX_PRESET);
    expect(POLICY_PRESETS[3]?.policy).toBe(FIRELY_PRESET);
    expect(POLICY_PRESETS[4]?.policy).toBe(SMILE_CDR_PRESET);
    expect(POLICY_PRESETS[5]?.policy).toBe(ONTOSERVER_PRESET);
  });

  it("cites documentation for every preset", () => {
    // The rule the preset list is written under: a preset asserts what another
    // system will do with a token, and an assertion nobody can check does not
    // belong in a security product. A vendor whose contract could not be found
    // gets no preset - which is why Medplum is absent.
    for (const preset of POLICY_PRESETS) {
      expect(preset.references.length).toBeGreaterThan(0);
      for (const reference of preset.references) {
        expect(reference.label.length).toBeGreaterThan(0);
        expect(reference.url.startsWith("https://")).toBe(true);
      }
    }
    expect(POLICY_PRESETS.map((preset) => preset.id)).not.toContain("medplum");
  });

  it("gives every rule in every preset a unique id", () => {
    for (const preset of POLICY_PRESETS) {
      const ids = [
        ...preset.policy.scopeGrants,
        ...preset.policy.claimRules,
        ...(preset.policy.scopeMappings ?? []),
        ...preset.policy.contextRules,
      ].map((rule) => rule.id);
      expect(ids.every((id) => id !== undefined)).toBe(true);
      expect(new Set(ids).size).toBe(ids.length);
    }
  });
});
