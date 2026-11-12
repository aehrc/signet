/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The identity claims an OAuth / OpenID Connect endpoint releases.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  assembleAccessTokenClaims,
  assembleIdTokenClaims,
} from "./assemble.js";
import { evaluatePolicy } from "../policy/evaluate.js";
import { OAUTH_BASELINE_PRESET } from "../policy/presets.js";
import { parseScopes } from "../scopes/index.js";

import type { EvaluationContext, EvaluationUser } from "../policy/types.js";

const API = "https://api.example.org/v1";

const ALICE: EvaluationUser = {
  id: "u1",
  username: "alice",
  fhirUser: "Practitioner/should-never-appear",
  displayName: "Alice Example",
  email: "alice@example.org",
  emailVerified: true,
  roles: ["buyer"],
  attributes: {},
};

/** An OAuth endpoint's context for a signed-in user requesting scopes. */
function context(
  requested: string,
  user: EvaluationUser = ALICE,
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
    user,
    requested: parseScopes(requested, "oauth").scopes,
    context: {},
    grantType: "authorization_code",
  };
}

/** The ID token claims for a request, with the registered claims dropped. */
function identity(
  requested: string,
  user: EvaluationUser = ALICE,
): Record<string, unknown> {
  const evaluated = context(requested, user);
  const claims = assembleIdTokenClaims({
    evaluation: evaluatePolicy(OAUTH_BASELINE_PRESET, evaluated),
    context: evaluated,
    issuance: { jti: "j", issuedAt: 1000, subject: "u1" },
  });
  const { iss, aud, sub, exp, iat, jti, azp, ...rest } = claims;
  expect([iss, aud, sub, exp, iat, jti, azp]).toHaveLength(7);
  return rest;
}

describe("assembleIdTokenClaims - OAuth endpoint", () => {
  it("releases nothing about the user for openid alone", () => {
    expect(identity("openid")).toEqual({});
  });

  it("releases name and preferred_username for profile", () => {
    expect(identity("openid profile")).toEqual({
      name: "Alice Example",
      preferred_username: "alice",
    });
  });

  it("releases email and email_verified for email", () => {
    expect(identity("openid email")).toEqual({
      email: "alice@example.org",
      email_verified: true,
    });
  });

  it("releases no email claims for a user with no email", () => {
    expect(identity("openid email", { ...ALICE, email: null })).toEqual({});
  });

  it("never releases fhirUser, roles or a profile reference", () => {
    const claims = identity("openid profile email fhirUser");
    expect(claims).not.toHaveProperty("fhirUser");
    expect(claims).not.toHaveProperty("profile");
    expect(claims).not.toHaveProperty("roles");
  });
});

describe("assembleAccessTokenClaims - OAuth endpoint", () => {
  it("addresses the token to the endpoint's audience", () => {
    const evaluated = context("openid");
    expect(
      assembleAccessTokenClaims({
        evaluation: evaluatePolicy(OAUTH_BASELINE_PRESET, evaluated),
        context: evaluated,
        issuance: { jti: "j", issuedAt: 1000, subject: "u1" },
      }).aud,
    ).toBe(API);
  });
});
