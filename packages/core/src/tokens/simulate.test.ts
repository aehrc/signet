/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { simulateIssuance } from "./simulate.js";
import { PATHLING_PRESET, SMART_BASELINE_PRESET } from "../policy/presets.js";
import { parseScopes } from "../scopes/index.js";

import type { EvaluationContext } from "../policy/types.js";

/** A context describing a clinician launching an app with a patient in hand. */
function contextFor(
  scopes: string,
  overrides: Partial<EvaluationContext> = {},
): EvaluationContext {
  return {
    endpoint: {
      tenantSlug: "demo",
      slug: "pathling",
      issuer: "https://signet.test/t/demo/e/pathling",
      fhirBaseUrl: "https://pathling.test/fhir",
    },
    client: {
      clientId: "app-1",
      name: "Test app",
      type: "confidential-symmetric",
      attributes: {},
    },
    user: {
      id: "user-1",
      fhirUser: "Practitioner/prac-1",
      displayName: "Test Clinician",
      roles: ["practitioner"],
      attributes: {},
    },
    requested: parseScopes(scopes).scopes,
    context: { patient: "pat-1" },
    grantType: "authorization_code",
    ...overrides,
  };
}

const issuance = {
  jti: "11111111-1111-1111-1111-111111111111",
  issuedAt: 1_800_000_000,
  subject: "user-1",
};

describe("simulateIssuance", () => {
  it("reports the scopes a policy granted", () => {
    const result = simulateIssuance({
      policy: SMART_BASELINE_PRESET,
      context: contextFor("patient/Observation.rs openid fhirUser"),
      issuance,
    });

    expect(result.scope).toContain("patient/Observation.rs");
    expect(result.evaluation.deniedScopes).toEqual([]);
  });

  it("assembles the registered claims the server would sign", () => {
    const result = simulateIssuance({
      policy: SMART_BASELINE_PRESET,
      context: contextFor("patient/Observation.rs"),
      issuance,
    });

    expect(result.accessTokenClaims.iss).toBe(
      "https://signet.test/t/demo/e/pathling",
    );
    // The resource server, not the client: this is the claim a FHIR server checks
    // itself against, and getting it wrong in the preview would hide a real
    // misconfiguration.
    expect(result.accessTokenClaims.aud).toBe("https://pathling.test/fhir");
    expect(result.accessTokenClaims.exp).toBe(
      issuance.issuedAt + result.accessTokenTtl,
    );
    expect(result.accessTokenClaims.jti).toBe(issuance.jti);
  });

  it("shows the vendor claims a mapping policy produces", () => {
    const result = simulateIssuance({
      policy: PATHLING_PRESET,
      context: contextFor("patient/Observation.rs"),
      issuance,
    });

    expect(result.accessTokenClaims["authorities"]).toEqual([
      "pathling:read:Observation",
      "pathling:search",
      "pathling:read-resource",
      "pathling:export",
      "pathling:sql-run",
      "pathling:sql-export",
      "pathling:jobs",
    ]);
  });

  it("shows an ID token when openid was granted", () => {
    const result = simulateIssuance({
      policy: SMART_BASELINE_PRESET,
      context: contextFor("openid fhirUser patient/Observation.rs"),
      issuance,
    });

    expect(result.idTokenClaims?.aud).toBe("app-1");
    expect(result.idTokenClaims?.fhirUser).toBe("Practitioner/prac-1");
  });

  it("shows no ID token when openid was not requested", () => {
    const result = simulateIssuance({
      policy: SMART_BASELINE_PRESET,
      context: contextFor("patient/Observation.rs"),
      issuance,
    });

    expect(result.idTokenClaims).toBeNull();
  });

  it("shows no ID token on an endpoint that is not an OIDC provider", () => {
    const result = simulateIssuance({
      policy: SMART_BASELINE_PRESET,
      context: contextFor("openid patient/Observation.rs"),
      issuance,
      supportsOpenIdConnect: false,
    });

    expect(result.idTokenClaims).toBeNull();
  });

  it("reports the launch context parameters the response would carry", () => {
    const result = simulateIssuance({
      policy: SMART_BASELINE_PRESET,
      context: contextFor("patient/Observation.rs"),
      issuance,
    });

    expect(result.responseParameters).toMatchObject({
      patient: "pat-1",
      need_patient_banner: true,
    });
  });

  it("reports a refresh token for a confidential client granted offline access", () => {
    const result = simulateIssuance({
      policy: SMART_BASELINE_PRESET,
      context: contextFor("patient/Observation.rs offline_access"),
      issuance,
    });

    expect(result.wouldIssueRefreshToken).toBe(true);
  });

  it("never reports a refresh token for a backend service", () => {
    const result = simulateIssuance({
      policy: SMART_BASELINE_PRESET,
      context: contextFor("system/Observation.rs offline_access", {
        user: null,
        grantType: "client_credentials",
      }),
      issuance,
    });

    expect(result.wouldIssueRefreshToken).toBe(false);
  });

  it("explains a refusal rather than silently granting nothing", () => {
    const result = simulateIssuance({
      policy: SMART_BASELINE_PRESET,
      // Writing is granted by no preset, so this must come back denied with a
      // reason the console can show beside the rule list.
      context: contextFor("patient/Observation.cud"),
      issuance,
    });

    expect(result.evaluation.grantedScopes).toEqual([]);
    expect(result.evaluation.deniedScopes[0]?.reason).toBeDefined();
  });

  it("reports a narrowing, so the preview is honest about what was reduced", () => {
    const result = simulateIssuance({
      policy: SMART_BASELINE_PRESET,
      context: contextFor("patient/Observation.cruds"),
      issuance,
    });

    expect(result.evaluation.narrowedScopes[0]?.granted).toMatchObject({
      permissions: ["r", "s"],
    });
  });
});
