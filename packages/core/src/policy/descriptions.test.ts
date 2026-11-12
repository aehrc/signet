/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { grantingRuleDescriptions } from "./descriptions.js";
import { evaluatePolicy } from "./evaluate.js";
import { OAUTH_BASELINE_PRESET } from "./presets.js";
import { parseScopes } from "../scopes/parse.js";

import type { EvaluationContext, PolicyDocument } from "./types.js";

const POLICY: PolicyDocument = {
  ...OAUTH_BASELINE_PRESET,
  scopeGrants: [
    {
      id: "orders",
      description: "Read your orders.",
      match: "orders:read",
      allow: true,
    },
    { id: "invoices", match: "invoices:read", allow: true },
    { id: "blank", description: "  ", match: "notes:read", allow: true },
    {
      id: "deny",
      description: "Never shown.",
      match: "orders:write",
      allow: false,
    },
  ],
};

/** Evaluates the policy for an OAuth request asking for the given scopes. */
function evaluate(scope: string) {
  const context: EvaluationContext = {
    endpoint: {
      tenantSlug: "t",
      slug: "e",
      issuer: "https://signet.test/t/t/e/e",
      kind: "oauth",
      audience: "https://api.test",
    },
    client: { clientId: "app", name: "App", type: "public", attributes: {} },
    user: null,
    requested: parseScopes(scope, "oauth").scopes,
    context: {},
    grantType: "authorization_code",
  };
  return evaluatePolicy(POLICY, context);
}

describe("grantingRuleDescriptions", () => {
  it("names each granted scope by its rule's description", () => {
    expect(
      grantingRuleDescriptions(evaluate("orders:read").grantingRules),
    ).toEqual({ "orders:read": "Read your orders." });
  });

  it("omits a scope whose rule has no description, or a blank one", () => {
    expect(
      grantingRuleDescriptions(
        evaluate("invoices:read notes:read").grantingRules,
      ),
    ).toEqual({});
  });

  it("omits a refused scope, even when the refusing rule has a description", () => {
    expect(
      grantingRuleDescriptions(evaluate("orders:write").grantingRules),
    ).toEqual({});
  });
});
