/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { buildIntrospectionResponse } from "./introspect.js";

import type { IntrospectableToken } from "./types.js";

const NOW = 1_700_000_100;

/** Builds a stored token, overriding only what a test cares about. */
function token(
  overrides: Partial<IntrospectableToken> = {},
): IntrospectableToken {
  return {
    jti: "jti-1",
    clientId: "client-abc",
    subject: "user-1",
    scope: "patient/Observation.rs launch/patient",
    issuer: "https://signet.example.org/t/demo/e/pathling",
    audience: "https://fhir.example.org/fhir",
    issuedAt: 1_700_000_000,
    expiresAt: 1_700_000_300,
    revokedAt: null,
    launchContext: {},
    idTokenClaims: null,
    ...overrides,
  };
}

describe("buildIntrospectionResponse", () => {
  it("reports an active token with the RFC 7662 fields", () => {
    const response = buildIntrospectionResponse(token(), NOW);
    expect(response).toEqual({
      active: true,
      scope: "patient/Observation.rs launch/patient",
      client_id: "client-abc",
      exp: 1_700_000_300,
      iat: 1_700_000_000,
      sub: "user-1",
      aud: "https://fhir.example.org/fhir",
      iss: "https://signet.example.org/t/demo/e/pathling",
      token_type: "Bearer",
    });
  });

  describe("an invalid token discloses nothing at all", () => {
    it("returns only active:false for an unknown token", () => {
      const response = buildIntrospectionResponse(null, NOW);
      expect(response).toEqual({ active: false });
      expect(Object.keys(response)).toEqual(["active"]);
    });

    it("returns only active:false for an expired token", () => {
      const response = buildIntrospectionResponse(
        token({ launchContext: { patient: "123" } }),
        1_700_000_400,
      );
      expect(response).toEqual({ active: false });
    });

    it("returns only active:false for a revoked token", () => {
      const response = buildIntrospectionResponse(
        token({
          revokedAt: 1_700_000_050,
          launchContext: { patient: "123" },
          idTokenClaims: { fhirUser: "Practitioner/abc" },
        }),
        NOW,
      );
      expect(response).toEqual({ active: false });
    });

    it("leaks neither scope, subject nor launch context", () => {
      const secretive = token({
        scope: "system/*.cruds",
        subject: "user-secret",
        revokedAt: 1_700_000_050,
        launchContext: { patient: "patient-secret" },
        idTokenClaims: { fhirUser: "Practitioner/secret" },
      });
      const serialised = JSON.stringify(
        buildIntrospectionResponse(secretive, NOW),
      );
      expect(serialised).toBe('{"active":false}');
    });

    it("treats revocation as decisive even before expiry", () => {
      const response = buildIntrospectionResponse(token({ revokedAt: 0 }), NOW);
      expect(response.active).toBe(false);
    });
  });

  describe("expiry boundary", () => {
    it("is active in the second before expiry", () => {
      expect(buildIntrospectionResponse(token(), 1_700_000_299).active).toBe(
        true,
      );
    });

    it("is inactive at the instant of expiry", () => {
      expect(buildIntrospectionResponse(token(), 1_700_000_300).active).toBe(
        false,
      );
    });

    it("is active at the instant of issuance", () => {
      expect(buildIntrospectionResponse(token(), 1_700_000_000).active).toBe(
        true,
      );
    });
  });

  describe("launch context", () => {
    it("echoes patient and encounter", () => {
      const response = buildIntrospectionResponse(
        token({ launchContext: { patient: "123", encounter: "456" } }),
        NOW,
      );
      expect(response.patient).toBe("123");
      expect(response.encounter).toBe("456");
    });

    it("publishes the banner and style hints under their SMART wire names", () => {
      const response = buildIntrospectionResponse(
        token({
          launchContext: {
            needPatientBanner: false,
            smartStyleUrl: "https://ehr.example.org/style.json",
          },
        }),
        NOW,
      );
      expect(response.need_patient_banner).toBe(false);
      expect(response.smart_style_url).toBe(
        "https://ehr.example.org/style.json",
      );
      expect(response).not.toHaveProperty("needPatientBanner");
      expect(response).not.toHaveProperty("smartStyleUrl");
    });

    it("echoes fhirContext, intent and tenant", () => {
      const fhirContext = [
        { reference: "DiagnosticReport/789" },
        { canonical: "http://example.org/Questionnaire/q1|1.0.0" },
      ];
      const response = buildIntrospectionResponse(
        token({
          launchContext: {
            fhirContext,
            intent: "reconcile-medications",
            tenant: "t1",
          },
        }),
        NOW,
      );
      expect(response.fhirContext).toEqual(fhirContext);
      expect(response.intent).toBe("reconcile-medications");
      expect(response.tenant).toBe("t1");
    });

    it("omits absent context keys entirely", () => {
      const response = buildIntrospectionResponse(token(), NOW);
      for (const key of [
        "patient",
        "encounter",
        "fhirContext",
        "intent",
        "tenant",
        "need_patient_banner",
        "smart_style_url",
      ]) {
        expect(response).not.toHaveProperty(key);
      }
    });
  });

  describe("ID token claims", () => {
    it("includes the identity claims when one was issued", () => {
      const response = buildIntrospectionResponse(
        token({
          idTokenClaims: {
            fhirUser: "Practitioner/abc",
            profile: "Practitioner/abc",
            azp: "client-abc",
          },
        }),
        NOW,
      );
      expect(response.fhirUser).toBe("Practitioner/abc");
      expect(response.profile).toBe("Practitioner/abc");
      expect(response.azp).toBe("client-abc");
    });

    it("never lets ID token claims displace the introspected token's own fields", () => {
      // An ID token is audienced to the client and may have a different
      // lifetime; reporting those would misdescribe the access token.
      const response = buildIntrospectionResponse(
        token({
          idTokenClaims: {
            iss: "https://other.example",
            aud: "client-abc",
            sub: "someone-else",
            exp: 99_999_999_999,
            iat: 0,
            scope: "system/*.cruds",
            client_id: "another-client",
            active: false,
            token_type: "mac",
          },
        }),
        NOW,
      );
      expect(response).toEqual({
        active: true,
        scope: "patient/Observation.rs launch/patient",
        client_id: "client-abc",
        exp: 1_700_000_300,
        iat: 1_700_000_000,
        sub: "user-1",
        aud: "https://fhir.example.org/fhir",
        iss: "https://signet.example.org/t/demo/e/pathling",
        token_type: "Bearer",
      });
    });

    it("never lets launch context displace the introspected token's own fields", () => {
      const response = buildIntrospectionResponse(
        token({
          launchContext: { patient: "123" },
          idTokenClaims: null,
        }),
        NOW,
      );
      expect(response.active).toBe(true);
      expect(response.patient).toBe("123");
      expect(response.scope).toBe("patient/Observation.rs launch/patient");
    });
  });

  it("does not mutate the stored token", () => {
    const stored = token({
      launchContext: { patient: "123" },
      idTokenClaims: { fhirUser: "Practitioner/abc" },
    });
    buildIntrospectionResponse(stored, NOW);
    expect(stored.launchContext).toEqual({ patient: "123" });
    expect(stored.idTokenClaims).toEqual({ fhirUser: "Practitioner/abc" });
  });

  it("returns an independent object for each invalid token", () => {
    // The inactive response is a shared constant, so a caller must not be able
    // to mutate it into a leaky one for the next request.
    const first = buildIntrospectionResponse(null, NOW) as Record<
      string,
      unknown
    >;
    first.scope = "system/*.cruds";
    expect(buildIntrospectionResponse(null, NOW)).toEqual({ active: false });
  });
});
