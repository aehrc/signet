/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { evaluatePolicy } from "./evaluate.js";
import {
  AIDBOX_PRESET,
  FIRELY_PRESET,
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
} from "./types.js";
import type { LaunchContext } from "../launch/types.js";
import type { Permission, Scope, ScopeContext } from "../scopes/types.js";

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

/**
 * The Pathling preset with its grant rules replaced by an allow-everything rule.
 *
 * The mapping table is what this file is really about, and it can only be
 * exercised for scopes that were granted. Separating the two means a change to
 * the preset's grants can never quietly stop the mapping assertions from running.
 */
const PATHLING_MAPPING_HARNESS: PolicyDocument = {
  ...PATHLING_PRESET,
  scopeGrants: [
    { match: "*/*.cruds", allow: true },
    { match: "openid", allow: true },
    { match: "fhirUser", allow: true },
  ],
};

/** The authorities the Pathling mapping produces for a scope string. */
function authoritiesFor(
  requested: string,
  overrides: ContextOverrides = {},
): readonly string[] {
  const result = evaluatePolicy(
    PATHLING_MAPPING_HARNESS,
    context({ ...overrides, requested }),
  );
  const authorities = result.claims["authorities"];
  if (authorities === undefined) {
    return [];
  }
  if (!Array.isArray(authorities)) {
    throw new TypeError("Expected the authorities claim to be an array");
  }
  return authorities as readonly string[];
}

// Every authority Pathling understands. Anything outside this grammar would be
// silently ignored by Pathling, which is indistinguishable from a policy that
// grants nothing at all.
const DATA_AUTHORITY = /^pathling:(?:read|write)(?::[A-Z][A-Za-z]*)?$/;
const OPERATION_AUTHORITIES = new Set<string>([
  "pathling:search",
  "pathling:import",
  "pathling:import-pnp",
  "pathling:update",
  "pathling:delete",
  "pathling:batch",
  "pathling:bulk-submit",
  "pathling:export",
  "pathling:view-run",
  "pathling:view-export",
]);

/** Operation authorities that need a read authority to be usable. */
const READ_OPERATIONS = new Set<string>([
  "pathling:search",
  "pathling:export",
  "pathling:view-run",
  "pathling:view-export",
]);

/** Operation authorities that need a write authority to be usable. */
const WRITE_OPERATIONS = new Set<string>([
  "pathling:import",
  "pathling:import-pnp",
  "pathling:update",
  "pathling:delete",
  "pathling:batch",
  "pathling:bulk-submit",
]);

/**
 * Administrative operations no SMART scope may ever imply.
 *
 * Bulk import can overwrite a whole data warehouse and the view operations can
 * read across every resource type at once, so both must be granted deliberately.
 */
const NEVER_IMPLIED: readonly string[] = [
  "pathling:import",
  "pathling:import-pnp",
  "pathling:batch",
  "pathling:bulk-submit",
  "pathling:view-run",
  "pathling:view-export",
];

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
 */
function expectedAuthorities(
  scopeContext: ScopeContext,
  resourceType: string,
  permissions: readonly Permission[],
): readonly string[] {
  const suffix = resourceType === "*" ? "" : `:${resourceType}`;
  const has = (permission: Permission): boolean =>
    permissions.includes(permission);
  const expected: string[] = [];

  if (has("r") || has("s")) {
    expected.push(`pathling:read${suffix}`);
  }
  if (has("s")) {
    expected.push("pathling:search");
  }
  if (scopeContext === "system" && has("r")) {
    expected.push("pathling:export");
  }
  if (has("c") || has("u") || has("d")) {
    expected.push(`pathling:write${suffix}`);
  }
  if (has("c") || has("u")) {
    expected.push("pathling:update");
  }
  if (has("d")) {
    expected.push("pathling:delete");
  }
  return expected;
}

describe("PATHLING_PRESET - the two mandated cases", () => {
  it("maps patient/Observation.rs to a read and a search authority", () => {
    expect(authoritiesFor("patient/Observation.rs")).toEqual([
      "pathling:read:Observation",
      "pathling:search",
    ]);
  });

  it("maps system/*.rs to read, search and export", () => {
    expect(
      authoritiesFor("system/*.rs", { grantType: "client_credentials" }),
    ).toEqual(["pathling:read", "pathling:search", "pathling:export"]);
  });
});

describe("PATHLING_PRESET - authority table", () => {
  it.each([
    ["patient/Observation.r", ["pathling:read:Observation"]],
    ["patient/Observation.s", ["pathling:read:Observation", "pathling:search"]],
    [
      "patient/Observation.rs",
      ["pathling:read:Observation", "pathling:search"],
    ],
    ["patient/*.r", ["pathling:read"]],
    ["patient/*.rs", ["pathling:read", "pathling:search"]],
    ["user/Patient.r", ["pathling:read:Patient"]],
    ["user/Patient.rs", ["pathling:read:Patient", "pathling:search"]],
    ["user/*.rs", ["pathling:read", "pathling:search"]],
    ["system/Patient.r", ["pathling:read:Patient", "pathling:export"]],
    [
      "system/Patient.rs",
      ["pathling:read:Patient", "pathling:search", "pathling:export"],
    ],
    ["system/*.r", ["pathling:read", "pathling:export"]],
    ["system/*.s", ["pathling:read", "pathling:search"]],
    ["system/*.rs", ["pathling:read", "pathling:search", "pathling:export"]],
    [
      "patient/Observation.c",
      ["pathling:write:Observation", "pathling:update"],
    ],
    [
      "patient/Observation.u",
      ["pathling:write:Observation", "pathling:update"],
    ],
    [
      "patient/Observation.d",
      ["pathling:write:Observation", "pathling:delete"],
    ],
    [
      "patient/Observation.cu",
      ["pathling:write:Observation", "pathling:update"],
    ],
    [
      "patient/Observation.cud",
      ["pathling:write:Observation", "pathling:update", "pathling:delete"],
    ],
    [
      "user/Patient.cruds",
      [
        "pathling:read:Patient",
        "pathling:search",
        "pathling:write:Patient",
        "pathling:update",
        "pathling:delete",
      ],
    ],
    [
      "system/*.cruds",
      [
        "pathling:read",
        "pathling:search",
        "pathling:export",
        "pathling:write",
        "pathling:update",
        "pathling:delete",
      ],
    ],
    // A v1 scope is normalised before mapping, so it behaves as its v2 form.
    [
      "patient/Observation.read",
      ["pathling:read:Observation", "pathling:search"],
    ],
    [
      "patient/Observation.write",
      ["pathling:write:Observation", "pathling:update", "pathling:delete"],
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
      "pathling:write:Observation",
      "pathling:update",
      "pathling:delete",
    ]);
  });

  it("emits a bare read authority alongside a typed one when both were asked for", () => {
    expect(authoritiesFor("patient/*.r patient/Observation.r")).toEqual([
      "pathling:read",
      "pathling:read:Observation",
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
      ).toEqual(expectedAuthorities(scopeContext, resourceType, permissions));
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
    "never implies an administrative operation for %s/%s.%s",
    (scopeContext, resourceType, permissions) => {
      const requested = `${scopeContext}/${resourceType}.${permissions.join("")}`;
      const authorities = authoritiesFor(requested, {
        grantType: "client_credentials",
      });
      for (const administrative of NEVER_IMPLIED) {
        expect(authorities).not.toContain(administrative);
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

  it("never emits an export authority outside the system context", () => {
    for (const [scopeContext, resourceType, permissions] of cases) {
      if (scopeContext === "system") {
        continue;
      }
      expect(
        authoritiesFor(
          `${scopeContext}/${resourceType}.${permissions.join("")}`,
        ),
      ).not.toContain("pathling:export");
    }
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
      "pathling:export",
    ]);
  });

  it("denies writes, because the write grant ships disabled", () => {
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

  it("never emits the import authority, because that mapping ships disabled", () => {
    // Checked through the harness so the disabled grant rule is not what makes
    // this pass.
    expect(
      authoritiesFor("system/*.cruds", { grantType: "client_credentials" }),
    ).not.toContain("pathling:import");
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

describe("POLICY_PRESETS", () => {
  it("lists every preset with unique ids and non-empty descriptions", () => {
    expect(POLICY_PRESETS.map((preset) => preset.id)).toEqual([
      "smart-baseline",
      "pathling",
      "aidbox",
      "firely",
      "smile-cdr",
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
