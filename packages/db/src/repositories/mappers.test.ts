/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  epochSeconds,
  toCapabilityConfig,
  toDefaultLaunchContext,
  toEvaluationClient,
  toEvaluationEndpoint,
  toEvaluationUser,
  toIntrospectableToken,
} from "./mappers.js";

import type { Client } from "../schema/clients.js";
import type { Endpoint, EndUser } from "../schema/endpoints.js";
import type { AccessToken } from "../schema/runtime.js";

const ISSUED = new Date("2026-01-01T12:00:00.000Z");
const EXPIRES = new Date("2026-01-01T12:05:00.000Z");

const endpoint: Endpoint = {
  id: "11111111-1111-1111-1111-111111111111",
  tenantId: "22222222-2222-2222-2222-222222222222",
  slug: "pathling",
  name: "Pathling",
  description: null,
  fhirBaseUrl: "https://fhir.example.org/fhir",
  supportsEhrLaunch: true,
  supportsStandaloneLaunch: true,
  supportsAuthorizePost: false,
  allowsPublicClients: true,
  allowsConfidentialSymmetricClients: true,
  allowsConfidentialAsymmetricClients: false,
  supportsOpenIdConnect: true,
  supportsPatientBanner: true,
  supportsStyling: false,
  supportsEhrPatientContext: true,
  supportsEhrEncounterContext: false,
  supportsStandalonePatientContext: true,
  supportsStandaloneEncounterContext: false,
  supportsOfflineAccess: true,
  supportsOnlineAccess: false,
  supportsPatientScopes: true,
  supportsUserScopes: true,
  supportsV1Scopes: false,
  supportsV2Scopes: true,
  supportsBackendServices: true,
  supportsDynamicRegistration: false,
  scopesSupported: ["openid", "patient/*.rs"],
  userAccessBrandBundle: null,
  userAccessBrandIdentifier: null,
  accessTokenTtl: 300,
  refreshTokenTtl: 2_592_000,
  authMode: "local",
  consentMode: "always",
  isProduction: true,
  status: "active",
  createdAt: ISSUED,
  updatedAt: ISSUED,
};

const client: Client = {
  id: "33333333-3333-3333-3333-333333333333",
  endpointId: endpoint.id,
  clientId: "growth-chart",
  name: "Growth Chart",
  description: null,
  logoUrl: null,
  clientType: "public",
  secretHash: null,
  secretExpiresAt: null,
  jwks: null,
  jwksUri: null,
  jwksCachedAt: null,
  redirectUris: ["https://app.example.org/callback"],
  launchUri: null,
  grantTypes: ["authorization_code"],
  allowedScopes: ["patient/*.rs"],
  status: "active",
  contactEmail: null,
  attributes: { vendor: "example" },
  createdBy: null,
  createdAt: ISSUED,
  updatedAt: ISSUED,
};

const endUser: EndUser = {
  id: "44444444-4444-4444-4444-444444444444",
  endpointId: endpoint.id,
  username: "alice",
  passwordHash: "$argon2id$never-emitted",
  fhirUserReference: "Practitioner/123",
  displayName: "Alice Example",
  roles: ["clinician"],
  attributes: { department: "cardiology" },
  defaultContext: null,
  isPersona: false,
  createdAt: ISSUED,
  disabledAt: null,
};

const accessToken: AccessToken = {
  jti: "55555555-5555-5555-5555-555555555555",
  endpointId: endpoint.id,
  clientId: client.id,
  subject: endUser.id,
  scope: "patient/Observation.rs launch/patient",
  issuer: "https://signet.example.org/t/demo/e/pathling",
  audience: "https://fhir.example.org/fhir",
  launchContext: { patient: "Patient/1" },
  idTokenClaims: null,
  issuedAt: ISSUED,
  expiresAt: EXPIRES,
  revokedAt: null,
};

describe("epochSeconds", () => {
  it("converts to whole seconds since the epoch", () => {
    expect(epochSeconds(ISSUED)).toBe(1_767_268_800);
  });

  it("truncates rather than rounding up, so exp is never later than the row", () => {
    const withMillis = new Date(ISSUED.getTime() + 999);
    expect(epochSeconds(withMillis)).toBe(epochSeconds(ISSUED));
  });
});

describe("toIntrospectableToken", () => {
  it("carries the OAuth client identifier, not the surrogate key", () => {
    const token = toIntrospectableToken(accessToken, client.clientId);
    expect(token.clientId).toBe("growth-chart");
  });

  it("preserves the issuer and audience the token was minted with", () => {
    const token = toIntrospectableToken(accessToken, client.clientId);
    expect(token.issuer).toBe(accessToken.issuer);
    expect(token.audience).toBe(accessToken.audience);
  });

  it("reports timestamps as epoch seconds", () => {
    const token = toIntrospectableToken(accessToken, client.clientId);
    expect(token.issuedAt).toBe(epochSeconds(ISSUED));
    expect(token.expiresAt).toBe(epochSeconds(EXPIRES));
  });

  it("reports an unrevoked token with a null revocation time", () => {
    expect(toIntrospectableToken(accessToken, client.clientId).revokedAt).toBe(
      null,
    );
  });

  it("reports a revoked token's revocation time", () => {
    const revoked = { ...accessToken, revokedAt: EXPIRES };
    expect(toIntrospectableToken(revoked, client.clientId).revokedAt).toBe(
      epochSeconds(EXPIRES),
    );
  });

  it("passes the launch context through unchanged", () => {
    expect(
      toIntrospectableToken(accessToken, client.clientId).launchContext,
    ).toEqual({ patient: "Patient/1" });
  });
});

describe("toEvaluationEndpoint", () => {
  it("takes the issuer from the caller, since it is deployment configuration", () => {
    const issuer = "https://signet.example.org/t/demo/e/pathling";
    expect(toEvaluationEndpoint(endpoint, "demo", issuer)).toEqual({
      tenantSlug: "demo",
      slug: "pathling",
      issuer,
      fhirBaseUrl: endpoint.fhirBaseUrl,
    });
  });
});

describe("toEvaluationClient", () => {
  it("exposes the client's type and attributes to the policy", () => {
    expect(toEvaluationClient(client)).toEqual({
      clientId: "growth-chart",
      name: "Growth Chart",
      type: "public",
      attributes: { vendor: "example" },
    });
  });
});

describe("toEvaluationUser", () => {
  it("maps the FHIR user reference onto fhirUser", () => {
    expect(toEvaluationUser(endUser).fhirUser).toBe("Practitioner/123");
  });

  it("keeps a missing FHIR user as null rather than dropping the field", () => {
    const user = toEvaluationUser({ ...endUser, fhirUserReference: null });
    expect(user.fhirUser).toBe(null);
    expect("fhirUser" in user).toBe(true);
  });

  it("does not expose the password hash to a policy", () => {
    expect(JSON.stringify(toEvaluationUser(endUser))).not.toContain("argon2id");
  });
});

describe("toCapabilityConfig", () => {
  const issuer = "https://signet.example.org/t/demo/e/pathling";

  it("copies every capability flag from the row", () => {
    const config = toCapabilityConfig(endpoint, issuer);
    expect(config.supportsEhrLaunch).toBe(true);
    expect(config.supportsAuthorizePost).toBe(false);
    expect(config.allowsConfidentialAsymmetricClients).toBe(false);
    expect(config.supportsV1Scopes).toBe(false);
    expect(config.supportsV2Scopes).toBe(true);
    expect(config.supportsBackendServices).toBe(true);
    expect(config.supportsDynamicRegistration).toBe(false);
    expect(config.scopesSupported).toEqual(["openid", "patient/*.rs"]);
  });

  it("omits an unset brand bundle rather than publishing null", () => {
    const config = toCapabilityConfig(endpoint, issuer);
    expect("userAccessBrandBundle" in config).toBe(false);
    expect("userAccessBrandIdentifier" in config).toBe(false);
  });

  it("includes the brand bundle when the endpoint has one", () => {
    const config = toCapabilityConfig(
      {
        ...endpoint,
        userAccessBrandBundle: "https://brands.example.org/Bundle/1",
        userAccessBrandIdentifier: "https://brands.example.org|1",
      },
      issuer,
    );
    expect(config.userAccessBrandBundle).toBe(
      "https://brands.example.org/Bundle/1",
    );
    expect(config.userAccessBrandIdentifier).toBe(
      "https://brands.example.org|1",
    );
  });
});

describe("toDefaultLaunchContext", () => {
  it("returns an empty context for a user with no default", () => {
    expect(toDefaultLaunchContext(endUser)).toEqual({});
  });

  it("returns a persona's pre-set context", () => {
    const persona = {
      ...endUser,
      isPersona: true,
      defaultContext: { patient: "Patient/7", needPatientBanner: true },
    };
    expect(toDefaultLaunchContext(persona)).toEqual({
      patient: "Patient/7",
      needPatientBanner: true,
    });
  });
});
