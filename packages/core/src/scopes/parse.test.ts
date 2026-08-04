/**
 * Author: John Grimes
 */

import { describe, expect, it } from "vitest";

import { parseScope, parseScopes } from "./parse.js";
import { formatScope } from "./serialise.js";

import type { ResourceScope, Scope } from "./types.js";

/** Parses a scope, failing the test if it was rejected. */
function parsed(raw: string): Scope {
  const result = parseScope(raw);
  if (!result.ok) {
    throw new Error(
      `Expected "${raw}" to parse, got ${result.code}: ${result.message}`,
    );
  }
  return result.scope;
}

/** Parses a scope expected to be a resource scope. */
function resource(raw: string): ResourceScope {
  const scope = parsed(raw);
  if (scope.kind !== "resource") {
    throw new Error(
      `Expected "${raw}" to be a resource scope, got ${scope.kind}`,
    );
  }
  return scope;
}

/** Returns the error code for a scope expected to be rejected. */
function rejection(raw: string): string {
  const result = parseScope(raw);
  if (result.ok) {
    throw new Error(`Expected "${raw}" to be rejected, but it parsed`);
  }
  return result.code;
}

describe("parseScope - resource scopes", () => {
  it("parses each access context", () => {
    expect(resource("patient/Observation.rs").context).toBe("patient");
    expect(resource("user/Observation.rs").context).toBe("user");
    expect(resource("system/Observation.rs").context).toBe("system");
  });

  it("parses the resource type and permissions", () => {
    const scope = resource("patient/Observation.rs");
    expect(scope.resourceType).toBe("Observation");
    expect(scope.permissions).toEqual(["r", "s"]);
    expect(scope.parameters).toEqual([]);
  });

  it("accepts the wildcard resource type", () => {
    expect(resource("system/*.cruds").resourceType).toBe("*");
  });

  it("accepts every in-order permission subset", () => {
    expect(resource("patient/Patient.c").permissions).toEqual(["c"]);
    expect(resource("patient/Patient.r").permissions).toEqual(["r"]);
    expect(resource("patient/Patient.cu").permissions).toEqual(["c", "u"]);
    expect(resource("patient/Patient.cud").permissions).toEqual([
      "c",
      "u",
      "d",
    ]);
    expect(resource("patient/Patient.rs").permissions).toEqual(["r", "s"]);
    expect(resource("patient/Patient.cruds").permissions).toEqual([
      "c",
      "r",
      "u",
      "d",
      "s",
    ]);
  });

  it("accepts multi-word resource types", () => {
    expect(resource("user/DiagnosticReport.rs").resourceType).toBe(
      "DiagnosticReport",
    );
    expect(resource("user/MedicationRequest.rs").resourceType).toBe(
      "MedicationRequest",
    );
  });
});

describe("parseScope - permission suffix validation", () => {
  it("rejects out-of-order permissions rather than silently reordering them", () => {
    // The spec permits rejection, and reordering would grant a set the client
    // never wrote - the wrong default for an authorization server.
    expect(rejection("patient/Observation.dus")).toBe("unordered-permissions");
    expect(rejection("patient/Observation.sr")).toBe("unordered-permissions");
    expect(rejection("patient/Observation.rc")).toBe("unordered-permissions");
  });

  it("rejects duplicate permission letters", () => {
    expect(rejection("patient/Observation.rr")).toBe("duplicate-permission");
    expect(rejection("patient/Observation.cc")).toBe("duplicate-permission");
  });

  it("rejects unknown permission letters", () => {
    expect(rejection("patient/Observation.x")).toBe("unknown-permission");
    expect(rejection("patient/Observation.rx")).toBe("unknown-permission");
  });

  it("rejects a missing permission suffix", () => {
    expect(rejection("patient/Observation")).toBe("missing-permissions");
    expect(rejection("patient/Observation.")).toBe("missing-permissions");
  });
});

describe("parseScope - SMART v1 compatibility", () => {
  it("normalises .read to .rs", () => {
    expect(resource("patient/Observation.read").permissions).toEqual([
      "r",
      "s",
    ]);
  });

  it("normalises .write to .cud", () => {
    expect(resource("patient/Observation.write").permissions).toEqual([
      "c",
      "u",
      "d",
    ]);
  });

  it("normalises .* to .cruds", () => {
    expect(resource("patient/Observation.*").permissions).toEqual([
      "c",
      "r",
      "u",
      "d",
      "s",
    ]);
  });

  it("normalises v1 wildcard scopes", () => {
    const scope = resource("patient/*.read");
    expect(scope.resourceType).toBe("*");
    expect(scope.permissions).toEqual(["r", "s"]);
  });

  it("reports v1 scopes in v2 form, so clients see what they actually got", () => {
    expect(formatScope(parsed("patient/Observation.read"))).toBe(
      "patient/Observation.rs",
    );
    expect(formatScope(parsed("user/Encounter.write"))).toBe(
      "user/Encounter.cud",
    );
    expect(formatScope(parsed("system/*.*"))).toBe("system/*.cruds");
  });
});

describe("parseScope - search parameter restrictions", () => {
  it("parses a single restriction", () => {
    const scope = resource(
      "patient/Observation.rs?category=http://terminology.hl7.org/CodeSystem/observation-category|laboratory",
    );
    expect(scope.parameters).toEqual([
      {
        name: "category",
        value:
          "http://terminology.hl7.org/CodeSystem/observation-category|laboratory",
      },
    ]);
  });

  it("parses multiple restrictions in written order", () => {
    const scope = resource(
      "patient/Observation.rs?category=laboratory&status=final",
    );
    expect(scope.parameters).toEqual([
      { name: "category", value: "laboratory" },
      { name: "status", value: "final" },
    ]);
  });

  it("allows a parameter name to repeat", () => {
    const scope = resource(
      "patient/Observation.rs?category=vital-signs&category=laboratory",
    );
    expect(scope.parameters).toHaveLength(2);
  });

  it("percent-decodes values", () => {
    const scope = resource("patient/Observation.rs?code=a%7Cb");
    expect(scope.parameters[0]?.value).toBe("a|b");
  });

  it("rejects malformed restrictions", () => {
    expect(rejection("patient/Observation.rs?")).toBe("malformed-parameters");
    expect(rejection("patient/Observation.rs?category")).toBe(
      "malformed-parameters",
    );
    expect(rejection("patient/Observation.rs?=laboratory")).toBe(
      "malformed-parameters",
    );
  });
});

describe("parseScope - launch scopes", () => {
  it("parses the bare launch scope used in an EHR launch", () => {
    expect(parsed("launch")).toEqual({ kind: "launch" });
  });

  it("parses launch/patient and launch/encounter", () => {
    expect(parsed("launch/patient")).toEqual({
      kind: "launch",
      resource: "patient",
    });
    expect(parsed("launch/encounter")).toEqual({
      kind: "launch",
      resource: "encounter",
    });
  });

  it("parses an extensible launch context type", () => {
    expect(parsed("launch/location")).toEqual({
      kind: "launch",
      resource: "location",
    });
  });

  it("parses a role parameter", () => {
    expect(
      parsed("launch/list?role=https://example.org/med-list-at-home"),
    ).toEqual({
      kind: "launch",
      resource: "list",
      role: "https://example.org/med-list-at-home",
    });
  });

  it("rejects a launch scope with no context type", () => {
    expect(rejection("launch/")).toBe("malformed");
  });
});

describe("parseScope - identity and refresh scopes", () => {
  it("parses OpenID Connect scopes", () => {
    expect(parsed("openid")).toEqual({ kind: "identity", name: "openid" });
    expect(parsed("fhirUser")).toEqual({ kind: "identity", name: "fhirUser" });
    expect(parsed("profile")).toEqual({ kind: "identity", name: "profile" });
  });

  it("parses refresh token scopes", () => {
    expect(parsed("offline_access")).toEqual({
      kind: "refresh",
      name: "offline_access",
    });
    expect(parsed("online_access")).toEqual({
      kind: "refresh",
      name: "online_access",
    });
  });
});

describe("parseScope - extension scopes", () => {
  it("passes through double-underscore experimental scopes", () => {
    expect(parsed("__profilePhoto.manage")).toEqual({
      kind: "custom",
      value: "__profilePhoto.manage",
    });
  });

  it("passes through full URI scopes", () => {
    expect(
      parsed("https://ehr.example.org/scopes/profilePhoto.manage"),
    ).toEqual({
      kind: "custom",
      value: "https://ehr.example.org/scopes/profilePhoto.manage",
    });
  });
});

describe("parseScope - rejections", () => {
  it("rejects an empty scope", () => {
    expect(rejection("")).toBe("empty");
  });

  it("rejects an unknown access context", () => {
    expect(rejection("admin/Observation.rs")).toBe("unknown-context");
    expect(rejection("Patient/Observation.rs")).toBe("unknown-context");
  });

  it("rejects an unrecognised bare word", () => {
    expect(rejection("everything")).toBe("malformed");
  });

  it("rejects a lower-case resource type", () => {
    expect(rejection("patient/observation.rs")).toBe("invalid-resource-type");
  });

  it("rejects a resource type containing punctuation", () => {
    expect(rejection("patient/Obs-ervation.rs")).toBe("invalid-resource-type");
  });
});

describe("parseScopes", () => {
  it("parses a space-delimited scope string in order", () => {
    const result = parseScopes(
      "launch/patient patient/Observation.rs openid fhirUser",
    );
    expect(result.rejected).toEqual([]);
    expect(result.scopes.map(formatScope)).toEqual([
      "launch/patient",
      "patient/Observation.rs",
      "openid",
      "fhirUser",
    ]);
  });

  it("tolerates arbitrary whitespace between scopes", () => {
    const result = parseScopes("  openid \n  fhirUser \t patient/Patient.r  ");
    expect(result.scopes).toHaveLength(3);
    expect(result.rejected).toEqual([]);
  });

  it("returns an empty result for an empty string", () => {
    expect(parseScopes("")).toEqual({ scopes: [], rejected: [] });
    expect(parseScopes("   ")).toEqual({ scopes: [], rejected: [] });
  });

  it("collects rejected scopes instead of throwing, so they can be audited", () => {
    const result = parseScopes(
      "patient/Observation.rs patient/Observation.dus admin/Patient.r",
    );
    expect(result.scopes.map(formatScope)).toEqual(["patient/Observation.rs"]);
    expect(result.rejected).toEqual([
      {
        raw: "patient/Observation.dus",
        code: "unordered-permissions",
        message: expect.stringContaining("cruds"),
      },
      {
        raw: "admin/Patient.r",
        code: "unknown-context",
        message: expect.stringContaining("admin"),
      },
    ]);
  });
});

describe("round-tripping", () => {
  it.each([
    "patient/Observation.rs",
    "user/DiagnosticReport.cruds",
    "system/*.rs",
    "patient/Observation.rs?category=laboratory",
    "patient/Observation.rs?category=laboratory&status=final",
    "launch",
    "launch/patient",
    "launch/list?role=https%3A%2F%2Fexample.org%2Fhome",
    "openid",
    "fhirUser",
    "offline_access",
    "__darkMode",
    "https://example.org/custom",
  ])("re-serialises %s unchanged", (raw) => {
    expect(formatScope(parsed(raw))).toBe(raw);
  });
});
