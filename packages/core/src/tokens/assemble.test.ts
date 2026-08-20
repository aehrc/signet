/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  assembleAccessTokenClaims,
  assembleIdTokenClaims,
  assembleTokenResponse,
  type IdTokenInput,
} from "./assemble.js";
import { parseScopes } from "../scopes/index.js";

import type { AccessTokenInput, TokenIssuanceParameters } from "./types.js";
import type {
  EvaluationContext,
  EvaluationUser,
  PolicyEvaluation,
} from "../policy/types.js";
import type { Scope } from "../scopes/types.js";

/** Parses a scope string, failing the test if anything was unparseable. */
function scopes(raw: string): readonly Scope[] {
  const result = parseScopes(raw);
  expect(result.rejected).toEqual([]);
  return result.scopes;
}

const PRACTITIONER: EvaluationUser = {
  id: "user-1",
  fhirUser: "Practitioner/abc",
  displayName: "Dr Alice Chen",
  roles: ["clinician"],
  attributes: {},
};

/** Builds an evaluation context, overriding only what a test cares about. */
function context(
  overrides: Partial<EvaluationContext> = {},
): EvaluationContext {
  return {
    endpoint: {
      tenantSlug: "demo",
      slug: "pathling",
      issuer: "https://signet.example.org/t/demo/e/pathling",
      fhirBaseUrl: "https://fhir.example.org/fhir",
    },
    client: {
      clientId: "client-abc",
      name: "Growth Chart",
      type: "public",
      attributes: {},
    },
    user: PRACTITIONER,
    requested: scopes("patient/Observation.rs"),
    context: { patient: "123" },
    grantType: "authorization_code",
    ...overrides,
  };
}

/** Builds a policy evaluation, overriding only what a test cares about. */
function evaluation(
  overrides: Partial<PolicyEvaluation> = {},
): PolicyEvaluation {
  return {
    grantedScopes: scopes("patient/Observation.rs"),
    deniedScopes: [],
    narrowedScopes: [],
    claims: {},
    contextParams: {},
    accessTokenTtl: 300,
    refreshTokenTtl: 86_400,
    ...overrides,
  };
}

const ISSUANCE: TokenIssuanceParameters = {
  jti: "jti-1",
  issuedAt: 1_700_000_000,
  subject: "user-1",
};

/** Builds access token input from partial pieces. */
function accessTokenInput(
  overrides: Partial<AccessTokenInput> = {},
): AccessTokenInput {
  return {
    evaluation: evaluation(),
    context: context(),
    issuance: ISSUANCE,
    ...overrides,
  };
}

describe("assembleAccessTokenClaims", () => {
  it("sets the registered claims from the endpoint and issuance parameters", () => {
    const claims = assembleAccessTokenClaims(accessTokenInput());

    expect(claims.iss).toBe("https://signet.example.org/t/demo/e/pathling");
    expect(claims.sub).toBe("user-1");
    expect(claims.jti).toBe("jti-1");
    expect(claims.iat).toBe(1_700_000_000);
    expect(claims.client_id).toBe("client-abc");
  });

  it("audiences the access token to the FHIR base URL, not the client", () => {
    const claims = assembleAccessTokenClaims(accessTokenInput());
    expect(claims.aud).toBe("https://fhir.example.org/fhir");
    expect(claims.aud).not.toBe("client-abc");
  });

  it("derives exp from the issuance time and the evaluated TTL", () => {
    const claims = assembleAccessTokenClaims(
      accessTokenInput({ evaluation: evaluation({ accessTokenTtl: 900 }) }),
    );
    expect(claims.exp).toBe(1_700_000_900);
  });

  it("formats the granted scopes, normalising v1 scopes to v2", () => {
    const claims = assembleAccessTokenClaims(
      accessTokenInput({
        evaluation: evaluation({
          grantedScopes: scopes("patient/Observation.read openid fhirUser"),
        }),
      }),
    );
    expect(claims.scope).toBe("patient/Observation.rs openid fhirUser");
  });

  it("reports the granted scopes, never the requested ones", () => {
    const claims = assembleAccessTokenClaims(
      accessTokenInput({
        context: context({ requested: scopes("patient/*.cruds") }),
        evaluation: evaluation({
          grantedScopes: scopes("patient/Observation.r"),
        }),
      }),
    );
    expect(claims.scope).toBe("patient/Observation.r");
  });

  it("emits an empty scope string when nothing was granted", () => {
    const claims = assembleAccessTokenClaims(
      accessTokenInput({ evaluation: evaluation({ grantedScopes: [] }) }),
    );
    expect(claims.scope).toBe("");
  });

  it("carries policy-emitted claims through", () => {
    const claims = assembleAccessTokenClaims(
      accessTokenInput({
        evaluation: evaluation({
          claims: {
            authorities: ["pathling:read:Observation"],
            patient_id: "123",
          },
        }),
      }),
    );
    expect(claims.authorities).toEqual(["pathling:read:Observation"]);
    expect(claims.patient_id).toBe("123");
  });

  it("preserves the structure of nested policy claim values", () => {
    const claims = assembleAccessTokenClaims(
      accessTokenInput({
        evaluation: evaluation({
          claims: { extension: { nested: [1, "two", null] } },
        }),
      }),
    );
    expect(claims.extension).toEqual({ nested: [1, "two", null] });
  });

  describe("policy claims can never displace a registered claim", () => {
    it("refuses a policy attempt to change the issuer", () => {
      const claims = assembleAccessTokenClaims(
        accessTokenInput({
          evaluation: evaluation({ claims: { iss: "https://evil.example" } }),
        }),
      );
      expect(claims.iss).toBe("https://signet.example.org/t/demo/e/pathling");
    });

    it("refuses a policy attempt to extend the lifetime", () => {
      const claims = assembleAccessTokenClaims(
        accessTokenInput({
          evaluation: evaluation({ claims: { exp: 99_999_999_999 } }),
        }),
      );
      expect(claims.exp).toBe(1_700_000_300);
    });

    it("refuses a policy attempt to widen the audience", () => {
      const claims = assembleAccessTokenClaims(
        accessTokenInput({
          evaluation: evaluation({
            claims: { aud: ["https://evil.example", "*"] },
          }),
        }),
      );
      expect(claims.aud).toBe("https://fhir.example.org/fhir");
    });

    it("refuses a policy attempt to impersonate another subject", () => {
      const claims = assembleAccessTokenClaims(
        accessTokenInput({
          evaluation: evaluation({ claims: { sub: "admin" } }),
        }),
      );
      expect(claims.sub).toBe("user-1");
    });

    it("refuses a policy attempt to escalate the scope claim", () => {
      const claims = assembleAccessTokenClaims(
        accessTokenInput({
          evaluation: evaluation({ claims: { scope: "system/*.cruds" } }),
        }),
      );
      expect(claims.scope).toBe("patient/Observation.rs");
    });

    it("refuses policy attempts on every server-owned claim at once", () => {
      const claims = assembleAccessTokenClaims(
        accessTokenInput({
          evaluation: evaluation({
            claims: {
              iss: "https://evil.example",
              aud: "https://evil.example",
              sub: "admin",
              exp: 99_999_999_999,
              iat: 0,
              jti: "forged",
              scope: "system/*.cruds",
              client_id: "another-client",
            },
          }),
        }),
      );
      expect(claims).toEqual({
        iss: "https://signet.example.org/t/demo/e/pathling",
        aud: "https://fhir.example.org/fhir",
        sub: "user-1",
        exp: 1_700_000_300,
        iat: 1_700_000_000,
        jti: "jti-1",
        scope: "patient/Observation.rs",
        client_id: "client-abc",
      });
    });
  });

  it("uses the client id as subject for a client credentials grant", () => {
    const claims = assembleAccessTokenClaims(
      accessTokenInput({
        context: context({
          user: null,
          grantType: "client_credentials",
          client: {
            clientId: "backend-svc",
            name: "Bulk Export",
            type: "confidential-asymmetric",
            attributes: {},
          },
        }),
        issuance: { ...ISSUANCE, subject: "backend-svc" },
        evaluation: evaluation({ grantedScopes: scopes("system/*.rs") }),
      }),
    );
    expect(claims.sub).toBe("backend-svc");
    expect(claims.client_id).toBe("backend-svc");
    expect(claims.scope).toBe("system/*.rs");
  });

  it("does not mutate its inputs", () => {
    const policyClaims = { patient_id: "123" };
    const input = accessTokenInput({
      evaluation: evaluation({ claims: policyClaims }),
    });
    assembleAccessTokenClaims(input);
    expect(policyClaims).toEqual({ patient_id: "123" });
  });
});

/** Builds ID token input from partial pieces. */
function idTokenInput(overrides: Partial<IdTokenInput> = {}): IdTokenInput {
  return {
    evaluation: evaluation({
      grantedScopes: scopes("openid fhirUser patient/Observation.rs"),
    }),
    context: context(),
    issuance: ISSUANCE,
    ...overrides,
  };
}

describe("assembleIdTokenClaims", () => {
  it("audiences the ID token to the client, not the FHIR server", () => {
    const claims = assembleIdTokenClaims(idTokenInput());
    expect(claims.aud).toBe("client-abc");
    expect(claims.aud).not.toBe("https://fhir.example.org/fhir");
  });

  it("sets azp to the client id", () => {
    expect(assembleIdTokenClaims(idTokenInput()).azp).toBe("client-abc");
  });

  it("sets the remaining registered claims", () => {
    const claims = assembleIdTokenClaims(idTokenInput());
    expect(claims.iss).toBe("https://signet.example.org/t/demo/e/pathling");
    expect(claims.sub).toBe("user-1");
    expect(claims.iat).toBe(1_700_000_000);
    expect(claims.jti).toBe("jti-1");
  });

  it("defaults its lifetime to the access token TTL", () => {
    const claims = assembleIdTokenClaims(idTokenInput());
    expect(claims.exp).toBe(1_700_000_300);
  });

  it("honours an explicit ID token TTL", () => {
    const claims = assembleIdTokenClaims(idTokenInput({ idTokenTtl: 60 }));
    expect(claims.exp).toBe(1_700_000_060);
  });

  it("includes fhirUser when the user has one and the scope was granted", () => {
    expect(assembleIdTokenClaims(idTokenInput()).fhirUser).toBe(
      "Practitioner/abc",
    );
  });

  it("omits fhirUser when the scope was not granted", () => {
    const claims = assembleIdTokenClaims(
      idTokenInput({
        evaluation: evaluation({ grantedScopes: scopes("openid") }),
      }),
    );
    expect(claims).not.toHaveProperty("fhirUser");
  });

  it("omits fhirUser when the user has no FHIR resource", () => {
    const claims = assembleIdTokenClaims(
      idTokenInput({
        context: context({ user: { ...PRACTITIONER, fhirUser: null } }),
      }),
    );
    expect(claims).not.toHaveProperty("fhirUser");
  });

  it("omits fhirUser when there is no user at all", () => {
    const claims = assembleIdTokenClaims(
      idTokenInput({ context: context({ user: null }) }),
    );
    expect(claims).not.toHaveProperty("fhirUser");
  });

  it("includes profile as a synonym for fhirUser when that scope was granted", () => {
    const claims = assembleIdTokenClaims(
      idTokenInput({
        evaluation: evaluation({
          grantedScopes: scopes("openid profile fhirUser"),
        }),
      }),
    );
    expect(claims.profile).toBe("Practitioner/abc");
    expect(claims.fhirUser).toBe("Practitioner/abc");
  });

  it("omits profile when only fhirUser was granted, and the reverse", () => {
    const onlyFhirUser = assembleIdTokenClaims(
      idTokenInput({
        evaluation: evaluation({ grantedScopes: scopes("openid fhirUser") }),
      }),
    );
    expect(onlyFhirUser).not.toHaveProperty("profile");

    const onlyProfile = assembleIdTokenClaims(
      idTokenInput({
        evaluation: evaluation({ grantedScopes: scopes("openid profile") }),
      }),
    );
    expect(onlyProfile).not.toHaveProperty("fhirUser");
    expect(onlyProfile.profile).toBe("Practitioner/abc");
  });

  it("includes nonce and auth_time only when supplied", () => {
    const without = assembleIdTokenClaims(idTokenInput());
    expect(without).not.toHaveProperty("nonce");
    expect(without).not.toHaveProperty("auth_time");

    const supplied = assembleIdTokenClaims(
      idTokenInput({
        issuance: { ...ISSUANCE, nonce: "n-0S6", authTime: 1_699_999_000 },
      }),
    );
    expect(supplied.nonce).toBe("n-0S6");
    expect(supplied.auth_time).toBe(1_699_999_000);
  });

  it("does not carry policy-emitted claims into the identity assertion", () => {
    const claims = assembleIdTokenClaims(
      idTokenInput({
        evaluation: evaluation({
          grantedScopes: scopes("openid fhirUser"),
          claims: { authorities: ["pathling:read:Observation"] },
        }),
      }),
    );
    expect(claims).not.toHaveProperty("authorities");
  });

  it("emits exactly the expected claim set for a full identity request", () => {
    const claims = assembleIdTokenClaims(
      idTokenInput({
        evaluation: evaluation({
          grantedScopes: scopes("openid fhirUser profile"),
        }),
        issuance: { ...ISSUANCE, nonce: "n-0S6", authTime: 1_699_999_000 },
      }),
    );
    expect(claims).toEqual({
      iss: "https://signet.example.org/t/demo/e/pathling",
      aud: "client-abc",
      sub: "user-1",
      exp: 1_700_000_300,
      iat: 1_700_000_000,
      jti: "jti-1",
      azp: "client-abc",
      nonce: "n-0S6",
      auth_time: 1_699_999_000,
      fhirUser: "Practitioner/abc",
      profile: "Practitioner/abc",
    });
  });
});

describe("assembleTokenResponse", () => {
  it("emits the standard fields with a Bearer token type", () => {
    const response = assembleTokenResponse({
      accessToken: "at-1",
      expiresIn: 300,
      scope: "patient/Observation.rs",
      contextParams: {},
    });
    expect(response).toEqual({
      access_token: "at-1",
      token_type: "Bearer",
      expires_in: 300,
      scope: "patient/Observation.rs",
    });
  });

  it("omits id_token and refresh_token rather than emitting undefined", () => {
    const response = assembleTokenResponse({
      accessToken: "at-1",
      expiresIn: 300,
      scope: "openid",
      contextParams: {},
    });
    expect(Object.keys(response)).not.toContain("id_token");
    expect(Object.keys(response)).not.toContain("refresh_token");
    expect(JSON.stringify(response)).not.toContain("undefined");
  });

  it("includes id_token and refresh_token when present", () => {
    const response = assembleTokenResponse({
      accessToken: "at-1",
      expiresIn: 300,
      scope: "openid offline_access",
      idToken: "idt-1",
      refreshToken: "rt-1",
      contextParams: {},
    });
    expect(response.id_token).toBe("idt-1");
    expect(response.refresh_token).toBe("rt-1");
  });

  it("merges launch context parameters in", () => {
    const response = assembleTokenResponse({
      accessToken: "at-1",
      expiresIn: 300,
      scope: "patient/Observation.rs",
      contextParams: {
        patient: "123",
        encounter: "456",
        need_patient_banner: false,
        smart_style_url: "https://ehr.example.org/style.json",
      },
    });
    expect(response.patient).toBe("123");
    expect(response.encounter).toBe("456");
    expect(response.need_patient_banner).toBe(false);
    expect(response.smart_style_url).toBe("https://ehr.example.org/style.json");
  });

  it("never lets context parameters overwrite a standard OAuth field", () => {
    const response = assembleTokenResponse({
      accessToken: "at-1",
      expiresIn: 300,
      scope: "patient/Observation.r",
      idToken: "idt-1",
      refreshToken: "rt-1",
      contextParams: {
        access_token: "forged",
        token_type: "mac",
        expires_in: 99_999_999,
        scope: "system/*.cruds",
        id_token: "forged-idt",
        refresh_token: "forged-rt",
      },
    });
    expect(response).toEqual({
      access_token: "at-1",
      token_type: "Bearer",
      expires_in: 300,
      scope: "patient/Observation.r",
      id_token: "idt-1",
      refresh_token: "rt-1",
    });
  });

  it("strips a reserved parameter even when the real field is absent", () => {
    // Otherwise a context rule could conjure an id_token the server never
    // issued, which a naive client might treat as an authenticated identity.
    const response = assembleTokenResponse({
      accessToken: "at-1",
      expiresIn: 300,
      scope: "patient/Observation.r",
      contextParams: { id_token: "forged", refresh_token: "forged" },
    });
    expect(response).not.toHaveProperty("id_token");
    expect(response).not.toHaveProperty("refresh_token");
  });

  it("does not mutate the supplied context parameters", () => {
    const contextParams = { patient: "123" };
    assembleTokenResponse({
      accessToken: "at-1",
      expiresIn: 300,
      scope: "patient/Observation.r",
      contextParams,
    });
    expect(contextParams).toEqual({ patient: "123" });
  });
});
