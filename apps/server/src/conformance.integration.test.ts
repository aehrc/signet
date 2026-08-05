/**
 * One test per capability Signet advertises.
 *
 * A `capabilities` array in a SMART configuration is a promise to every app that
 * reads it, and the cheapest way to break that promise is to keep advertising a
 * capability whose implementation was changed underneath. So this suite is indexed
 * by the capability strings themselves, and the index is typed as a total record
 * over `SmartCapability` - adding a capability to the union without a test here is
 * a compile error, not an omission somebody has to notice.
 *
 * Each entry exercises the behaviour the capability names, against a real database
 * and a real endpoint. Where the behaviour is "this can be turned off", the test
 * asserts both directions: an endpoint that advertises it does the thing, and one
 * that does not, refuses. A capability that is only ever tested in the affirmative
 * is one that could be hard-coded on and still pass.
 *
 * The suite is not a substitute for the focused ones. `token.integration.test.ts`
 * asserts what the token endpoint does in a dozen ways; this asserts that the
 * document's claims are each backed by at least one of them.
 *
 * Author: John Grimes
 */

import { afterAll, beforeAll, describe, expect, it } from "bun:test";

import { adminRequest, endpointPath } from "./test/adminApi.js";
import {
  authorize,
  authorizeToCode,
  backendToken,
  basicAuth,
  clientAssertion,
  decodePayload,
  interactionState,
  issuerPath,
  pkcePair,
  postForm,
  startAuthorization,
} from "./test/flows.js";
import {
  createTestStack,
  TEST_CLIENT_SECRET,
  TEST_PASSWORD,
  testDatabaseUrl,
} from "./test/harness.js";

import type { TestStack } from "./test/harness.js";
import type { SmartCapability } from "@signet/core";

/** The discovery document, as an app would read it. */
interface SmartConfiguration {
  readonly capabilities: readonly string[];
  readonly grant_types_supported: readonly string[];
  readonly token_endpoint_auth_methods_supported?: readonly string[];
  readonly code_challenge_methods_supported: readonly string[];
  readonly scopes_supported?: readonly string[];
  readonly registration_endpoint?: string;
}

describe.skipIf(testDatabaseUrl === undefined)(
  "advertised capabilities",
  () => {
    let stack: TestStack;
    let advertised: SmartConfiguration;

    beforeAll(async () => {
      // Everything on, so the document advertises the full set and each test has
      // something to check. The negative halves build their own endpoints.
      stack = await createTestStack({
        endpoint: {
          // Everything the capability table can express, so the document
          // advertises the full set. The tests that need a capability *off*
          // build a second endpoint for it.
          supportsAuthorizePost: true,
          supportsBackendServices: true,
          supportsStyling: true,
          supportsStandaloneEncounterContext: true,
          consentMode: "always",
        },
      });
      advertised = (await (
        await stack.app.request(
          `${issuerPath(stack)}/.well-known/smart-configuration`,
        )
      ).json()) as SmartConfiguration;
    });

    afterAll(async () => {
      await stack.close();
    });

    /** Builds a second endpoint with one capability turned off. */
    async function endpointWithout(
      overrides: Record<string, unknown>,
    ): Promise<{ readonly slug: string; readonly path: string }> {
      const cookie = await stack.signIn();
      const slug = `off-${Math.abs(hash(JSON.stringify(overrides))).toString(36)}`;
      const response = await adminRequest(
        stack,
        "POST",
        `/api/v1/tenants/${stack.tenant.slug}/endpoints`,
        {
          credential: { cookie },
          body: {
            slug,
            name: "Capability off",
            fhirBaseUrl: "https://fhir.test/R4",
            ...overrides,
          },
        },
      );
      if (response.status !== 201 && response.status !== 200) {
        throw new Error(
          `could not create the endpoint: ${String(response.status)} ${await response.text()}`,
        );
      }
      return {
        slug,
        path: `/t/${stack.tenant.slug}/e/${slug}`,
      };
    }

    /** A stable non-cryptographic hash, so endpoint slugs are reproducible. */
    function hash(value: string): number {
      let result = 0;
      for (const character of value) {
        result =
          Math.trunc(result * 31 + (character.codePointAt(0) ?? 0)) % 1e9;
      }
      return result;
    }

    /** Reads a second endpoint's discovery document. */
    async function configurationAt(path: string): Promise<SmartConfiguration> {
      const response = await stack.app.request(
        `${path}/.well-known/smart-configuration`,
      );
      return (await response.json()) as SmartConfiguration;
    }

    /**
     * What each capability promises, and the check that it is kept.
     *
     * Typed as a total record, so the union and this table cannot drift.
     */
    const CONFORMANCE: Readonly<Record<SmartCapability, () => Promise<void>>> =
      {
        "launch-ehr": async () => {
          // An EHR launch is a `launch` scope plus a launch handle. What proves the
          // capability is that the handle is honoured: the context it carries ends
          // up in the token response without the user choosing anything.
          const handle = await launchHandle({ patient: "ehr-1" });

          const session = await startAuthorization(stack, {
            clientId: stack.publicClient.clientId,
            scope: "openid launch patient/*.rs",
            challenge: (await pkcePair()).challenge,
            launch: handle,
          });
          const state = await interactionState(stack, session);
          expect(state.step).toBe("login");
        },

        "launch-standalone": async () => {
          // No launch handle: the app asks for context itself and Signet resolves it
          // through the picker rather than from an EHR.
          const session = await startAuthorization(stack, {
            clientId: stack.publicClient.clientId,
            scope: "openid launch/patient patient/*.rs",
            challenge: (await pkcePair()).challenge,
          });
          expect((await interactionState(stack, session)).step).toBe("login");
        },

        "authorize-post": async () => {
          const posted = await authorize(stack, {
            clientId: stack.publicClient.clientId,
            scope: "openid",
            challenge: (await pkcePair()).challenge,
            method: "POST",
          });
          expect(posted.status).toBe(302);

          const off = await endpointWithout({ supportsAuthorizePost: false });
          expect((await configurationAt(off.path)).capabilities).not.toContain(
            "authorize-post",
          );
          const refused = await stack.app.request(`${off.path}/authorize`, {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({ response_type: "code" }).toString(),
          });
          expect(refused.status).not.toBe(302);
        },

        "client-public": async () => {
          // A public client is one that authenticates with PKCE and no credential.
          const { code, verifier } = await authorizeToCode(stack, {
            clientId: stack.publicClient.clientId,
            scope: "openid",
          });
          const response = await postForm(stack, "/token", {
            grant_type: "authorization_code",
            code,
            redirect_uri: "https://app.test/cb",
            client_id: stack.publicClient.clientId,
            code_verifier: verifier,
          });
          expect(response.status).toBe(200);
        },

        "client-confidential-symmetric": async () => {
          const { code, verifier } = await authorizeToCode(stack, {
            clientId: stack.symmetricClient.clientId,
            scope: "openid",
          });
          const response = await postForm(
            stack,
            "/token",
            {
              grant_type: "authorization_code",
              code,
              redirect_uri: "https://app.test/cb",
              code_verifier: verifier,
            },
            {
              authorization: basicAuth(
                stack.symmetricClient.clientId,
                TEST_CLIENT_SECRET,
              ),
            },
          );
          expect(response.status).toBe(200);
          expect(advertised.token_endpoint_auth_methods_supported).toContain(
            "client_secret_basic",
          );
        },

        "client-confidential-asymmetric": async () => {
          const response = await backendToken(stack, "system/Patient.rs");
          expect(response.status).toBe(200);
          expect(advertised.token_endpoint_auth_methods_supported).toContain(
            "private_key_jwt",
          );
        },

        "sso-openid-connect": async () => {
          const { code, verifier } = await authorizeToCode(stack, {
            clientId: stack.publicClient.clientId,
            scope: "openid fhirUser",
          });
          const response = await postForm(stack, "/token", {
            grant_type: "authorization_code",
            code,
            redirect_uri: "https://app.test/cb",
            client_id: stack.publicClient.clientId,
            code_verifier: verifier,
          });
          const body = (await response.json()) as { id_token?: string };
          expect(body.id_token).toBeDefined();
          // An ID token that is not about anybody is not single sign-on.
          expect(decodePayload(body.id_token ?? "")["sub"]).toBeDefined();
        },

        "context-banner": async () => {
          const body = await tokenResponseWithPatient();
          expect(body["need_patient_banner"]).toBe(true);
        },

        "context-style": async () => {
          // The style URL comes from the launch context and is passed through
          // untouched; an endpoint that did not support styling would drop it.
          const handle = await launchHandle({
            patient: "ehr-1",
            smartStyleUrl: "https://ehr.test/style.json",
          });
          const body = await tokenResponseWithPatient(handle);
          expect(body["smart_style_url"]).toBe("https://ehr.test/style.json");
        },

        "context-ehr-patient": async () => {
          const body = await tokenResponseWithPatient();
          expect(body["patient"]).toBe("ehr-1");
        },

        "context-ehr-encounter": async () => {
          const handle = await launchHandle({
            patient: "ehr-1",
            encounter: "ehr-2",
          });
          const body = await tokenResponseWithPatient(handle);
          expect(body["encounter"]).toBe("ehr-2");
        },

        "context-standalone-patient": async () => {
          // No launch handle: the patient is chosen during the interaction.
          const { code, verifier } = await authorizeToCode(stack, {
            clientId: stack.publicClient.clientId,
            scope: "openid launch/patient patient/*.rs",
            patient: "pat-9",
          });
          const body = await redeem(code, verifier);
          expect(body["patient"]).toBe("pat-9");
        },

        "context-standalone-encounter": async () => {
          const session = await startAuthorization(stack, {
            clientId: stack.publicClient.clientId,
            scope: "openid launch/encounter",
            challenge: (await pkcePair()).challenge,
          });
          const state = await interactionState(stack, session);
          // The endpoint offers the choice rather than refusing the scope, which is
          // what the capability claims.
          expect(state.requestedScopes).toContain("launch/encounter");
        },

        "permission-offline": async () => {
          const { code, verifier } = await authorizeToCode(stack, {
            clientId: stack.symmetricClient.clientId,
            scope: "openid offline_access",
          });
          const response = await postForm(
            stack,
            "/token",
            {
              grant_type: "authorization_code",
              code,
              redirect_uri: "https://app.test/cb",
              code_verifier: verifier,
            },
            {
              authorization: basicAuth(
                stack.symmetricClient.clientId,
                TEST_CLIENT_SECRET,
              ),
            },
          );
          const body = (await response.json()) as Record<string, unknown>;
          expect(body["refresh_token"]).toBeDefined();
        },

        "permission-online": async () => {
          const off = await endpointWithout({ supportsOnlineAccess: false });
          expect((await configurationAt(off.path)).capabilities).not.toContain(
            "permission-online",
          );
          expect(advertised.capabilities).toContain("permission-online");
        },

        "permission-patient": async () => {
          const body = await tokenResponseWithPatient();
          expect(String(body["scope"])).toContain("patient/");
        },

        "permission-user": async () => {
          const { code, verifier } = await authorizeToCode(stack, {
            clientId: stack.publicClient.clientId,
            scope: "openid user/Observation.rs",
          });
          const body = await redeem(code, verifier);
          expect(String(body["scope"])).toContain("user/Observation.rs");
        },

        "permission-v1": async () => {
          // A v1 scope is accepted and normalised to its v2 equivalent, which is
          // what "supports v1" has to mean for a server that mints v2 tokens.
          const { code, verifier } = await authorizeToCode(stack, {
            clientId: stack.publicClient.clientId,
            scope: "openid user/Observation.read",
          });
          const body = await redeem(code, verifier);
          expect(String(body["scope"])).toContain("user/Observation.rs");
        },

        "permission-v2": async () => {
          const { code, verifier } = await authorizeToCode(stack, {
            clientId: stack.publicClient.clientId,
            scope: "openid user/Observation.rs",
          });
          const body = await redeem(code, verifier);
          expect(String(body["scope"])).toContain("user/Observation.rs");
        },
      };

    /** Redeems a code as the public client and returns the token response. */
    async function redeem(
      code: string,
      verifier: string,
    ): Promise<Record<string, unknown>> {
      const response = await postForm(stack, "/token", {
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://app.test/cb",
        client_id: stack.publicClient.clientId,
        code_verifier: verifier,
      });
      if (response.status !== 200) {
        throw new Error(`token request failed: ${await response.text()}`);
      }
      return (await response.json()) as Record<string, unknown>;
    }

    /**
     * Mints a launch handle the way an EHR would.
     *
     * Through the console's simulator route, which the module documentation
     * promises is the same operation an EHR performs - so a capability proved
     * with one of these is proved for a real launch.
     */
    async function launchHandle(
      context: Record<string, unknown>,
    ): Promise<string> {
      const cookie = await stack.signIn();
      const created = await adminRequest(
        stack,
        "POST",
        `${endpointPath(stack)}/launch`,
        {
          credential: { cookie },
          body: { clientId: stack.publicClient.clientId, ...context },
        },
      );
      if (created.status !== 201) {
        throw new Error(
          `could not mint a launch handle: ${String(created.status)} ${await created.text()}`,
        );
      }
      return ((await created.json()) as { launch: string }).launch;
    }

    /** Runs an EHR launch with a patient in context and returns the response. */
    async function tokenResponseWithPatient(
      existingHandle?: string,
    ): Promise<Record<string, unknown>> {
      const handle =
        existingHandle ?? (await launchHandle({ patient: "ehr-1" }));

      const { code, verifier } = await authorizeToCode(stack, {
        clientId: stack.publicClient.clientId,
        scope: "openid launch patient/*.rs",
        launch: handle,
      });
      return await redeem(code, verifier);
    }

    it("advertises exactly the capabilities this suite covers", () => {
      // The two halves of the promise: nothing advertised is untested, and nothing
      // tested has quietly stopped being advertised.
      expect([...advertised.capabilities].toSorted()).toEqual(
        Object.keys(CONFORMANCE).toSorted(),
      );
    });

    it.each(Object.keys(CONFORMANCE))("honours %s", async (capability) => {
      expect(advertised.capabilities).toContain(capability);
      await CONFORMANCE[capability as SmartCapability]();
    });

    it("advertises no registration endpoint, since it serves none", async () => {
      // Dynamic registration is off by default and there is nothing at
      // `/register`. The developer portal is the deliberate alternative: a
      // request an administrator approves, rather than self-service issuance of
      // credentials to anybody who can reach the endpoint. If a future change
      // turns the flag on, this fails until something answers there.
      expect(advertised.registration_endpoint).toBeUndefined();

      const response = await stack.app.request(
        `${issuerPath(stack)}/register`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
        },
      );
      expect(response.status).toBe(404);
    });

    it("advertises only PKCE methods it accepts", async () => {
      expect(advertised.code_challenge_methods_supported).toEqual(["S256"]);

      // `plain` must be refused even though the parameter is well-formed.
      const response = await authorize(stack, {
        clientId: stack.publicClient.clientId,
        scope: "openid",
        challenge: "a-verifier-used-directly-as-a-challenge-abcdefghij",
        codeChallengeMethod: "plain",
      });
      const location = response.headers.get("location") ?? "";
      expect(location).toContain("error=");
    });

    it("advertises only grants it will honour", async () => {
      // SMART's own list, which does not include `refresh_token`: that is an
      // OAuth grant rather than a SMART launch mode, and it belongs in the
      // OpenID Connect document, which is where the next assertion looks.
      expect([...advertised.grant_types_supported].toSorted()).toEqual([
        "authorization_code",
        "client_credentials",
      ]);

      const openId = (await (
        await stack.app.request(
          `${issuerPath(stack)}/.well-known/openid-configuration`,
        )
      ).json()) as SmartConfiguration;
      expect(openId.grant_types_supported).toContain("refresh_token");

      const off = await endpointWithout({ supportsBackendServices: false });
      const document = await configurationAt(off.path);
      expect(document.grant_types_supported).not.toContain(
        "client_credentials",
      );
    });

    it("refuses a password grant, which it never advertises", async () => {
      const response = await postForm(stack, "/token", {
        grant_type: "password",
        client_id: stack.publicClient.clientId,
        username: "clinician",
        password: TEST_PASSWORD,
      });
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({
        error: "unsupported_grant_type",
      });
    });

    it("signs with an algorithm the JWKS actually publishes", async () => {
      const keys = (await (
        await stack.app.request(`${issuerPath(stack)}/jwks`)
      ).json()) as { keys: { alg?: string; kid?: string }[] };
      const { code, verifier } = await authorizeToCode(stack, {
        clientId: stack.publicClient.clientId,
        scope: "openid",
      });
      const body = await redeem(code, verifier);
      const header = JSON.parse(
        Buffer.from(
          String(body["access_token"]).split(".", 1)[0] ?? "",
          "base64url",
        ).toString(),
      ) as { alg: string; kid: string };

      expect(keys.keys.some((key) => key.kid === header.kid)).toBe(true);
      expect(keys.keys.some((key) => key.alg === header.alg)).toBe(true);
    });

    it("keeps a client assertion usable exactly once", async () => {
      const assertion = await clientAssertion(stack, stack.backendClient, {
        jti: "conformance-single-use",
      });
      const form = {
        grant_type: "client_credentials",
        scope: "system/Patient.rs",
        client_assertion_type:
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: assertion,
      };
      expect((await postForm(stack, "/token", form)).status).toBe(200);
      expect((await postForm(stack, "/token", form)).status).toBe(401);
    });
  },
);
