/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { validateAuthorizeRequest } from "./authorizeRequest.js";

import type {
  AuthorizeClient,
  AuthorizeEndpoint,
  AuthorizeParams,
  AuthorizeValidation,
} from "./authorizeRequest.js";

const FHIR_BASE = "https://fhir.example.org/R4";
const REDIRECT = "https://app.example.org/cb";

/** A 43-character base64url string, the only shape an S256 challenge takes. */
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

const endpoint: AuthorizeEndpoint = {
  status: "active",
  fhirBaseUrl: FHIR_BASE,
  supportsEhrLaunch: true,
  supportsStandaloneLaunch: true,
  allowsPublicClients: true,
  allowsConfidentialSymmetricClients: true,
  allowsConfidentialAsymmetricClients: true,
  supportsOpenIdConnect: true,
  supportsStandalonePatientContext: true,
  supportsStandaloneEncounterContext: true,
  supportsOfflineAccess: true,
  supportsOnlineAccess: true,
  supportsPatientScopes: true,
  supportsUserScopes: true,
  supportsV1Scopes: true,
  supportsV2Scopes: true,
};

const client: AuthorizeClient = {
  clientId: "app",
  clientType: "public",
  status: "active",
  redirectUris: [REDIRECT],
  grantTypes: ["authorization_code", "refresh_token"],
  allowedScopes: [
    "openid",
    "fhirUser",
    "launch",
    "launch/patient",
    "launch/encounter",
    "offline_access",
    "online_access",
    "patient/*.cruds",
    "user/*.cruds",
  ],
};

const params: AuthorizeParams = {
  responseType: "code",
  clientId: "app",
  redirectUri: REDIRECT,
  scope: "openid fhirUser launch/patient patient/Observation.rs",
  state: "st",
  aud: FHIR_BASE,
  codeChallenge: CHALLENGE,
  codeChallengeMethod: "S256",
};

function validate(
  overrides: {
    params?: Partial<AuthorizeParams>;
    endpoint?: Partial<AuthorizeEndpoint>;
    client?: Partial<AuthorizeClient> | null;
  } = {},
): AuthorizeValidation {
  return validateAuthorizeRequest({
    params: { ...params, ...overrides.params },
    endpoint: { ...endpoint, ...overrides.endpoint },
    client:
      overrides.client === null
        ? undefined
        : { ...client, ...overrides.client },
  });
}

/** Reads the refusal from a validation that is expected to have failed. */
function refusalOf(result: AuthorizeValidation) {
  if (result.ok) {
    throw new Error("expected the request to be refused");
  }
  return result.refusal;
}

describe("validateAuthorizeRequest", () => {
  it("accepts a standalone launch", () => {
    const result = validate();
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.request).toMatchObject({
      clientId: "app",
      redirectUri: REDIRECT,
      state: "st",
      aud: FHIR_BASE,
      codeChallenge: CHALLENGE,
      codeChallengeMethod: "S256",
      launchMode: "standalone",
      launch: undefined,
      requestsPatientContext: true,
      requestsEncounterContext: false,
    });
    expect(result.request.requestedScopes).toEqual([
      "openid",
      "fhirUser",
      "launch/patient",
      "patient/Observation.rs",
    ]);
  });

  it("accepts an EHR launch and records the handle", () => {
    const result = validate({
      params: { scope: "launch openid patient/Observation.rs", launch: "xyz" },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.request.launchMode).toBe("ehr");
    expect(result.request.launch).toBe("xyz");
  });

  it("normalises v1 permission suffixes", () => {
    const result = validate({ params: { scope: "patient/Observation.read" } });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.request.scopes).toEqual([
      {
        kind: "resource",
        context: "patient",
        resourceType: "Observation",
        permissions: ["r", "s"],
        parameters: [],
      },
    ]);
    // The raw form is preserved for the session row and the audit trail.
    expect(result.request.requestedScopes).toEqual([
      "patient/Observation.read",
    ]);
  });

  describe("refusals that must not redirect", () => {
    it("refuses a missing client_id", () => {
      expect(refusalOf(validate({ params: { clientId: undefined } }))).toEqual({
        mode: "direct",
        error: "invalid_request",
        description: "client_id is required",
      });
    });

    it("refuses an unknown client", () => {
      expect(refusalOf(validate({ client: null })).mode).toBe("direct");
    });

    it("refuses a redirect_uri that does not match", () => {
      const refusal = refusalOf(
        validate({ params: { redirectUri: "https://attacker.example/cb" } }),
      );
      expect(refusal).toEqual({
        mode: "direct",
        error: "invalid_request",
        description: "redirect_uri does not match a registered value",
      });
    });

    it("refuses a missing redirect_uri", () => {
      expect(
        refusalOf(validate({ params: { redirectUri: undefined } })).mode,
      ).toBe("direct");
    });

    it("does not redirect an error before the redirect URI is proved", () => {
      // The response_type is also wrong here; the redirect URI failure must win,
      // or the server would have redirected to an unvalidated destination.
      const refusal = refusalOf(
        validate({
          params: {
            redirectUri: "https://attacker.example/cb",
            responseType: "token",
          },
        }),
      );
      expect(refusal.mode).toBe("direct");
    });
  });

  describe("refusals delivered by redirect", () => {
    it("echoes state and targets the validated redirect URI", () => {
      const refusal = refusalOf(
        validate({ params: { responseType: "token" } }),
      );
      expect(refusal).toEqual({
        mode: "redirect",
        redirectUri: REDIRECT,
        error: "unsupported_response_type",
        description: "Only response_type=code is supported",
        state: "st",
      });
    });

    it("omits state when the request had none", () => {
      const refusal = refusalOf(
        validate({ params: { responseType: "token", state: undefined } }),
      );
      expect(refusal.mode === "redirect" && "state" in refusal).toBe(false);
    });

    it("refuses a disabled endpoint", () => {
      expect(
        refusalOf(validate({ endpoint: { status: "disabled" } })),
      ).toMatchObject({ error: "temporarily_unavailable" });
    });

    it.each(["pending", "suspended", "rejected"])(
      "refuses a %s client registration",
      (status) => {
        expect(refusalOf(validate({ client: { status } }))).toMatchObject({
          error: "unauthorized_client",
        });
      },
    );

    it("refuses a client not registered for the authorization_code grant", () => {
      expect(
        refusalOf(validate({ client: { grantTypes: ["client_credentials"] } })),
      ).toMatchObject({ error: "unauthorized_client" });
    });

    it("refuses a client type the endpoint does not accept", () => {
      expect(
        refusalOf(validate({ endpoint: { allowsPublicClients: false } })),
      ).toMatchObject({ error: "unauthorized_client" });
      expect(
        refusalOf(
          validate({
            client: { clientType: "confidential-symmetric" },
            endpoint: { allowsConfidentialSymmetricClients: false },
          }),
        ),
      ).toMatchObject({ error: "unauthorized_client" });
      expect(
        refusalOf(
          validate({
            client: { clientType: "confidential-asymmetric" },
            endpoint: { allowsConfidentialAsymmetricClients: false },
          }),
        ),
      ).toMatchObject({ error: "unauthorized_client" });
    });

    it("requires PKCE", () => {
      expect(
        refusalOf(
          validate({
            params: {
              codeChallenge: undefined,
              codeChallengeMethod: undefined,
            },
          }),
        ),
      ).toMatchObject({ error: "invalid_request" });
    });

    it("refuses the plain PKCE method", () => {
      expect(
        refusalOf(validate({ params: { codeChallengeMethod: "plain" } })),
      ).toMatchObject({ error: "invalid_request" });
    });

    it("refuses a challenge that is not a base64url SHA-256 digest", () => {
      expect(
        refusalOf(validate({ params: { codeChallenge: "too-short" } })),
      ).toMatchObject({ error: "invalid_request" });
      expect(
        refusalOf(validate({ params: { codeChallenge: `${CHALLENGE}=` } })),
      ).toMatchObject({ error: "invalid_request" });
    });

    it("requires aud", () => {
      expect(
        refusalOf(validate({ params: { aud: undefined } })).description,
      ).toContain("aud is required");
    });

    it("refuses another server's aud", () => {
      expect(
        refusalOf(validate({ params: { aud: "https://other.example/fhir" } })),
      ).toMatchObject({ error: "invalid_request" });
    });

    it("requires a scope", () => {
      expect(refusalOf(validate({ params: { scope: "" } }))).toMatchObject({
        error: "invalid_scope",
      });
      expect(refusalOf(validate({ params: { scope: "   " } }))).toMatchObject({
        error: "invalid_scope",
      });
      expect(
        refusalOf(validate({ params: { scope: undefined } })),
      ).toMatchObject({ error: "invalid_scope" });
    });

    it("refuses an unparseable scope", () => {
      const refusal = refusalOf(
        validate({ params: { scope: "openid patient/Observation.sr" } }),
      );
      expect(refusal).toMatchObject({ error: "invalid_scope" });
      expect(refusal.description).toContain("patient/Observation.sr");
    });

    it("refuses a scope outside the client's allowlist", () => {
      const refusal = refusalOf(
        validate({
          params: { scope: "patient/Observation.rs" },
          client: { allowedScopes: ["patient/Condition.rs"] },
        }),
      );
      expect(refusal).toMatchObject({ error: "invalid_scope" });
      expect(refusal.description).toContain("allowlist");
    });

    it("accepts a scope narrower than the allowlist entry", () => {
      expect(
        validate({
          params: { scope: "patient/Observation.r" },
          client: { allowedScopes: ["patient/*.rs"] },
        }).ok,
      ).toBe(true);
    });

    it("ignores an unparseable allowlist entry rather than failing the request", () => {
      expect(
        validate({
          params: { scope: "patient/Observation.rs" },
          client: { allowedScopes: ["nonsense!", "patient/*.rs"] },
        }).ok,
      ).toBe(true);
    });
  });

  describe("capability gating", () => {
    it("refuses v1 scopes when the endpoint does not advertise permission-v1", () => {
      const refusal = refusalOf(
        validate({
          params: { scope: "patient/Observation.read" },
          endpoint: { supportsV1Scopes: false },
        }),
      );
      expect(refusal.description).toContain("v1");
    });

    it("refuses v2 scopes when the endpoint does not advertise permission-v2", () => {
      const refusal = refusalOf(
        validate({
          params: { scope: "patient/Observation.rs" },
          endpoint: { supportsV2Scopes: false },
        }),
      );
      expect(refusal.description).toContain("v2");
    });

    it("accepts a v1 scope on an endpoint that only advertises v1", () => {
      expect(
        validate({
          params: { scope: "patient/Observation.read" },
          endpoint: { supportsV2Scopes: false },
        }).ok,
      ).toBe(true);
    });

    it("refuses patient-context scopes when not advertised", () => {
      expect(
        refusalOf(
          validate({
            params: { scope: "patient/Observation.rs" },
            endpoint: { supportsPatientScopes: false },
          }),
        ).description,
      ).toContain("patient-context");
    });

    it("refuses user-context scopes when not advertised", () => {
      expect(
        refusalOf(
          validate({
            params: { scope: "user/Observation.rs" },
            endpoint: { supportsUserScopes: false },
          }),
        ).description,
      ).toContain("user-context");
    });

    it("refuses openid when the endpoint has OpenID Connect off", () => {
      expect(
        refusalOf(
          validate({
            params: { scope: "openid" },
            endpoint: { supportsOpenIdConnect: false },
          }),
        ).description,
      ).toContain("OpenID Connect");
    });

    it("refuses offline_access when not advertised", () => {
      expect(
        refusalOf(
          validate({
            params: { scope: "offline_access" },
            endpoint: { supportsOfflineAccess: false },
          }),
        ).description,
      ).toContain("offline_access");
    });

    it("refuses online_access when not advertised", () => {
      expect(
        refusalOf(
          validate({
            params: { scope: "online_access" },
            endpoint: { supportsOnlineAccess: false },
          }),
        ).description,
      ).toContain("online_access");
    });

    it("refuses an EHR launch when not advertised", () => {
      expect(
        refusalOf(
          validate({
            params: { scope: "launch openid", launch: "xyz" },
            endpoint: { supportsEhrLaunch: false },
          }),
        ).description,
      ).toContain("EHR launch");
    });

    it("refuses a standalone launch when not advertised", () => {
      expect(
        refusalOf(validate({ endpoint: { supportsStandaloneLaunch: false } }))
          .description,
      ).toContain("standalone launch");
    });

    it("refuses standalone patient context when not advertised", () => {
      expect(
        refusalOf(
          validate({
            params: { scope: "launch/patient" },
            endpoint: { supportsStandalonePatientContext: false },
          }),
        ).description,
      ).toContain("patient context in a standalone launch");
    });

    it("refuses standalone encounter context when not advertised", () => {
      expect(
        refusalOf(
          validate({
            params: { scope: "launch/encounter" },
            endpoint: { supportsStandaloneEncounterContext: false },
          }),
        ).description,
      ).toContain("encounter context in a standalone launch");
    });

    it("allows patient context in an EHR launch on an endpoint with standalone context off", () => {
      expect(
        validate({
          params: { scope: "launch patient/Observation.rs", launch: "xyz" },
          endpoint: { supportsStandalonePatientContext: false },
        }).ok,
      ).toBe(true);
    });
  });

  describe("launch scope and handle agreement", () => {
    it("refuses the bare launch scope with no launch parameter", () => {
      expect(
        refusalOf(validate({ params: { scope: "launch openid" } })).description,
      ).toContain("launch scope requires a launch parameter");
    });

    it("accepts a launch parameter without the launch scope", () => {
      // Some EHRs pass the handle while the app asks only for the context scopes
      // it needs. That is interoperable, so it is not refused.
      expect(
        validate({ params: { scope: "launch/patient", launch: "xyz" } }).ok,
      ).toBe(true);
    });
  });

  it("reports encounter context when launch/encounter is requested", () => {
    const result = validate({ params: { scope: "launch/encounter" } });
    expect(result.ok && result.request.requestsEncounterContext).toBe(true);
  });
});
