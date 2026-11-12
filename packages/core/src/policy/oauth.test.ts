/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Policies on an OAuth / OpenID Connect endpoint: exact scope matching, the
 * kind-aware validator, the baseline preset and the granting-rule record.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { evaluatePolicy } from "./evaluate.js";
import {
  OAUTH_BASELINE_PRESET,
  POLICY_PRESETS,
  SMART_BASELINE_PRESET,
} from "./presets.js";
import { validatePolicy } from "./validate.js";
import { formatScope, parseScopes } from "../scopes/index.js";

import type {
  EvaluationContext,
  PolicyDocument,
  ScopeGrantRule,
} from "./types.js";

const API = "https://api.example.org/v1";

/** An OAuth endpoint's evaluation context requesting the given scopes. */
function oauthContext(
  requested: string,
  grantType: EvaluationContext["grantType"] = "authorization_code",
): EvaluationContext {
  return {
    endpoint: {
      tenantSlug: "demo",
      slug: "orders",
      issuer: "https://signet.example.org/t/demo/e/orders",
      kind: "oauth",
      audience: API,
    },
    client: {
      clientId: "client-1",
      name: "Orders app",
      type: "confidential-symmetric",
      attributes: {},
    },
    user:
      grantType === "client_credentials"
        ? null
        : {
            id: "u1",
            username: "alice",
            fhirUser: null,
            displayName: "Alice Example",
            email: "alice@example.org",
            emailVerified: true,
            roles: ["buyer"],
            attributes: {},
          },
    requested: parseScopes(requested, "oauth").scopes,
    context: {},
    grantType,
  };
}

/** A policy with the given grant rules and nothing else. */
function withGrants(scopeGrants: readonly ScopeGrantRule[]): PolicyDocument {
  return {
    version: 1,
    scopeGrants,
    claimRules: [],
    contextRules: [],
    defaults: { accessTokenTtl: 300, refreshTokenTtl: 3600 },
  };
}

/** The granted scopes as strings. */
function granted(policy: PolicyDocument, requested: string): string[] {
  return evaluatePolicy(policy, oauthContext(requested)).grantedScopes.map(
    (scope) => formatScope(scope),
  );
}

describe("evaluatePolicy - OAuth endpoint", () => {
  it("grants an opaque scope a rule names exactly", () => {
    expect(
      granted(
        withGrants([{ match: "orders:read", allow: true }]),
        "orders:read",
      ),
    ).toEqual(["orders:read"]);
  });

  it("refuses an opaque scope no rule names", () => {
    const evaluation = evaluatePolicy(
      withGrants([{ match: "orders:read", allow: true }]),
      oauthContext("orders:write"),
    );
    expect(evaluation.grantedScopes).toEqual([]);
    expect(evaluation.deniedScopes.map((denied) => denied.reason)).toEqual([
      "No grant rule matches this scope, and the default is to deny",
    ]);
  });

  it("gives a SMART wildcard pattern no wildcard meaning", () => {
    expect(
      granted(
        withGrants([{ match: "*/*.cruds", allow: true, narrow: true }]),
        "patient/Observation.rs */*.cruds",
      ),
    ).toEqual(["*/*.cruds"]);
  });

  it("matches a SMART-shaped string only by exact equality", () => {
    expect(
      granted(
        withGrants([{ match: "patient/Observation.rs", allow: true }]),
        "patient/Observation.read patient/Observation.rs",
      ),
    ).toEqual(["patient/Observation.rs"]);
  });

  it("records the rule that granted each scope, keyed by the scope", () => {
    const rule: ScopeGrantRule = {
      id: "grant-orders",
      description: "Read your orders",
      match: "orders:read",
      allow: true,
    };
    const evaluation = evaluatePolicy(
      withGrants([{ match: "openid", allow: true }, rule]),
      oauthContext("openid orders:read orders:write"),
    );
    expect(evaluation.grantingRules).toEqual([
      { scope: "openid", rule: { match: "openid", allow: true } },
      { scope: "orders:read", rule },
    ]);
  });

  it("exposes the user's username and email to templates", () => {
    const evaluation = evaluatePolicy(
      {
        ...withGrants([]),
        claimRules: [
          {
            when: { hasUser: true },
            emit: {
              who: "{{ user.username }}",
              mail: "{{ user.email }}",
              audience: "{{ endpoint.audience }}",
            },
          },
        ],
      },
      oauthContext(""),
    );
    expect(evaluation.claims).toEqual({
      who: "alice",
      mail: "alice@example.org",
      audience: API,
    });
  });
});

describe("evaluatePolicy - granting rules on a SMART endpoint", () => {
  it("records a narrowing rule as the rule that granted the narrowed scope", () => {
    const rule: ScopeGrantRule = {
      id: "read-only",
      match: "patient/*.rs",
      allow: true,
      narrow: true,
    };
    const evaluation = evaluatePolicy(withGrants([rule]), {
      ...oauthContext(""),
      endpoint: { ...oauthContext("").endpoint, kind: "smart" },
      requested: parseScopes("patient/Observation.cruds", "smart").scopes,
    });
    expect(evaluation.grantingRules).toEqual([
      { scope: "patient/Observation.cruds", rule },
    ]);
  });
});

describe("validatePolicy - OAuth endpoint", () => {
  it("accepts a rule naming an opaque scope", () => {
    expect(
      validatePolicy(
        withGrants([{ match: "orders:read", allow: true }]),
        "oauth",
      ).ok,
    ).toBe(true);
  });

  it("refuses the same rule on a SMART endpoint", () => {
    expect(
      validatePolicy(
        withGrants([{ match: "orders:read", allow: true }]),
        "smart",
      ).ok,
    ).toBe(false);
  });

  it("refuses a match expression that is not a scope-token", () => {
    const result = validatePolicy(
      withGrants([{ match: 'say "hi"', allow: true }]),
      "oauth",
    );
    expect(result.ok).toBe(false);
  });

  it("refuses requireContext and context conditions, which need a launch", () => {
    const result = validatePolicy(
      {
        ...withGrants([
          { match: "orders:read", allow: true, requireContext: ["patient"] },
        ]),
        claimRules: [{ when: { context: ["patient"] }, emit: { a: "b" } }],
      },
      "oauth",
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.issues.map((issue) => issue.path)).toEqual([
        "scopeGrants[0].requireContext",
        "claimRules[0].when.context",
      ]);
    }
  });

  it("refuses narrowing, which has nothing to narrow on an opaque scope", () => {
    const result = validatePolicy(
      withGrants([{ match: "orders:read", allow: true, narrow: true }]),
      "oauth",
    );
    expect(result.ok).toBe(false);
  });
});

describe("OAUTH_BASELINE_PRESET", () => {
  it("validates on an OAuth endpoint", () => {
    expect(validatePolicy(OAUTH_BASELINE_PRESET, "oauth").ok).toBe(true);
  });

  it("grants only the OpenID Connect scopes and offline_access", () => {
    expect(
      granted(
        OAUTH_BASELINE_PRESET,
        "openid profile email offline_access orders:read",
      ),
    ).toEqual(["openid", "profile", "email", "offline_access"]);
  });

  it("is offered for OAuth endpoints, and the SMART presets are not", () => {
    const oauthPresets = POLICY_PRESETS.filter(
      (preset) => preset.kind === "oauth",
    );
    expect(oauthPresets.map((preset) => preset.policy)).toEqual([
      OAUTH_BASELINE_PRESET,
    ]);
    expect(
      POLICY_PRESETS.find((preset) => preset.policy === SMART_BASELINE_PRESET)
        ?.kind,
    ).toBe("smart");
  });

  it("validates every preset under its own kind", () => {
    for (const preset of POLICY_PRESETS) {
      expect(validatePolicy(preset.policy, preset.kind).ok).toBe(true);
    }
  });
});
