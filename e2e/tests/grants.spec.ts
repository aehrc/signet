/**
 * The grants and client credentials a public standalone launch cannot reach.
 *
 * `launch.spec.ts` proves the flagship path: a public app, PKCE, a standalone
 * launch, and a token Pathling accepts. The plan asks for more than that - an EHR
 * launch carrying context, both confidential client types, refresh, introspection
 * and revocation - and each of those is here, against the same real Pathling in
 * the same real browser.
 *
 * Where a confidential client is involved the browser does the half a browser
 * really does. It follows the redirects and the person signs in and consents; the
 * code is then exchanged through Playwright's request context, because a client
 * that holds a secret exchanges codes from its server and an app that did it from
 * the page would be leaking its credential. That split is the point of the client
 * type, so the test is written the way the deployment is.
 *
 * **The sign-in budget.** End-user sign-ins are rate limited to ten a minute per
 * address, and the whole suite runs from one address inside a single window. This
 * file spends three of them and `launch.spec.ts` spends four, so a run has three
 * to spare for retries. Anything added here that signs in interactively has to
 * come out of that, which is why the negative cases below are driven through the
 * request context wherever the browser is not what is being tested.
 *
 * Author: John Grimes
 */

import { expect, test } from "@playwright/test";
import { importJWK, SignJWT } from "jose";

import { ASYMMETRIC_KID, ASYMMETRIC_PRIVATE_JWK } from "../support/keys.js";
import {
  choosePatient,
  completedTokenResponse,
  decideConsent,
  signIn,
} from "../support/launch.js";
import { APP, FHIR, ISSUER, SEED } from "../support/stack.js";

import type { APIRequestContext, Page } from "@playwright/test";

/** The redirect URI both browser-driven clients are registered with. */
const REDIRECT_URI = `${APP}/`;

/** HTTP Basic, as a confidential client presents it at the token endpoint. */
function basic(clientId: string, secret: string): string {
  return `Basic ${Buffer.from(`${clientId}:${secret}`).toString("base64")}`;
}

/**
 * Drives `/authorize` in the browser and returns the code it comes back with.
 *
 * The person signs in and consents; what the app would do next is the caller's
 * business, which is what lets one helper serve a confidential client.
 *
 * @param page - The browser page to drive.
 * @param options - How to authorize.
 * @param options.clientId - The client to authorize as.
 * @param options.scope - The scopes to request.
 * @param options.launch - A launch handle, for an EHR launch.
 * @param options.patient - The patient to choose when the request asks for one.
 * @returns The authorization code from the redirect.
 */
async function authorizeInBrowser(
  page: Page,
  options: {
    readonly clientId: string;
    readonly scope: string;
    readonly launch?: string;
    readonly patient?: string;
  },
): Promise<string> {
  const url = new URL(`${ISSUER}/authorize`);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", options.clientId);
  url.searchParams.set("redirect_uri", REDIRECT_URI);
  url.searchParams.set("scope", options.scope);
  url.searchParams.set("state", "e2e-state");
  url.searchParams.set("aud", FHIR);
  // A fixed verifier and its S256 challenge. PKCE is mandatory here even for a
  // client that also authenticates, and a fixed pair keeps the test readable
  // without weakening what is being asserted.
  url.searchParams.set("code_challenge", CHALLENGE);
  url.searchParams.set("code_challenge_method", "S256");
  if (options.launch !== undefined) {
    url.searchParams.set("launch", options.launch);
  }

  await page.goto(url.toString());
  await signIn(page);
  // A standalone request for patient-context scopes has to resolve a patient
  // before there is anything to consent to, so the picker comes first. An EHR
  // launch skips it, because the handle already carried one.
  if (options.patient !== undefined) {
    await choosePatient(page, options.patient);
  }
  await decideConsent(page, "Allow");

  // The redirect lands on the stub app's page. Its script finds no launch in
  // this tab and says so, which is expected: this client's code is exchanged
  // from a server, not from the page.
  await page.waitForURL((landed) => landed.searchParams.has("code"), {
    timeout: 20_000,
  });

  const landed = new URL(page.url());
  expect(landed.searchParams.get("state")).toBe("e2e-state");
  return landed.searchParams.get("code") ?? "";
}

/** The PKCE verifier the helper above uses, and its S256 challenge. */
const VERIFIER = "e2e-verifier-that-is-long-enough-to-be-valid-0123456789";
const CHALLENGE = "ngth4SzqfIMndaCwr_zp-rt1TYttTn_GzKKOsl-XS-w";

/**
 * A `private_key_jwt` client assertion.
 *
 * @param audience - The token endpoint, which is what the assertion is for.
 * @returns The signed compact JWT.
 */
async function clientAssertion(audience: string): Promise<string> {
  const key = await importJWK(ASYMMETRIC_PRIVATE_JWK, "ES384");
  return await new SignJWT({})
    .setProtectedHeader({ alg: "ES384", kid: ASYMMETRIC_KID })
    .setIssuer(SEED.asymmetricClientId)
    .setSubject(SEED.asymmetricClientId)
    .setAudience(audience)
    // A fresh `jti` per call: Signet records them and refuses a replay, so a
    // fixed one would pass once and fail on every later run.
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .setExpirationTime("2m")
    .sign(key);
}

test.describe("an EHR launch", () => {
  test("carries the context the EHR minted, without asking the user", async ({
    page,
    request,
  }) => {
    // The EHR mints a handle for the app it is about to open. It authenticates as
    // a registered client; there is no separate "EHR" credential type.
    const minted = await request.post(`${ISSUER}/launch-context`, {
      headers: {
        authorization: basic(
          SEED.confidentialClientId,
          SEED.confidentialSecret,
        ),
        "content-type": "application/json",
      },
      data: {
        patient: "pat-9",
        encounter: "enc-1",
        forClientId: SEED.publicClientId,
        needPatientBanner: true,
      },
    });
    expect(minted.status()).toBe(201);

    const { launch } = (await minted.json()) as { launch: string };
    expect(launch).toBeTruthy();

    // The app is opened the way an EHR opens it: `iss` and `launch`, nothing else.
    await page.goto(
      `${APP}/?iss=${encodeURIComponent(ISSUER)}&aud=${encodeURIComponent(FHIR)}&launch=${encodeURIComponent(launch)}&scope=${encodeURIComponent("openid fhirUser launch patient/*.rs")}`,
    );
    await signIn(page);
    await decideConsent(page, "Allow");

    const tokenResponse = await completedTokenResponse(page);

    // The context came from the handle. No picker was shown, and that is the
    // difference between an EHR launch and a standalone one: the EHR already
    // knows who the patient is, and asking again would be both redundant and a
    // chance to pick somebody else.
    expect(tokenResponse["patient"]).toBe("pat-9");
    expect(tokenResponse["encounter"]).toBe("enc-1");
    expect(tokenResponse["need_patient_banner"]).toBe(true);

    // And the token works against the real FHIR server.
    await expect(page.getByTestId("fhir-status")).toContainText(
      "answered 200",
      {
        timeout: 20_000,
      },
    );
  });

  test("consumes a launch handle, and refuses it the second time", async ({
    request,
  }) => {
    const minted = await request.post(`${ISSUER}/launch-context`, {
      headers: {
        authorization: basic(
          SEED.confidentialClientId,
          SEED.confidentialSecret,
        ),
        "content-type": "application/json",
      },
      data: { patient: "pat-9", forClientId: SEED.publicClientId },
    });
    const { launch } = (await minted.json()) as { launch: string };
    expect(launch).toBeTruthy();

    // The handle is consumed at `/authorize`, before anybody signs in, so both
    // presentations are plain requests and neither spends a sign-in.
    const present = async (handle: string) =>
      await request.get(
        `${ISSUER}/authorize?response_type=code&client_id=${SEED.publicClientId}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=${encodeURIComponent("openid launch patient/*.rs")}&state=x&aud=${encodeURIComponent(FHIR)}&code_challenge=${CHALLENGE}&code_challenge_method=S256&launch=${encodeURIComponent(handle)}`,
        { maxRedirects: 0 },
      );

    // The first presentation is accepted. Asserted by the *absence* of an OAuth
    // error on the redirect rather than by its status, because a refusal is also
    // a redirect - to the app, carrying `error` - and a status check alone could
    // not tell the two apart.
    const first = await present(launch);
    expect(
      new URL(first.headers()["location"] ?? "", ISSUER).searchParams.get(
        "error",
      ),
    ).toBeNull();

    // The second is refused, and says why. A handle that could be redeemed twice
    // would let anybody who saw it in an EHR's logs open the app as that patient.
    const second = await present(launch);
    const refusal = new URL(second.headers()["location"] ?? "", ISSUER);
    expect(refusal.searchParams.get("error")).toBe("invalid_request");
    expect(refusal.searchParams.get("error_description")).toContain(
      "already been used",
    );

    // A handle that was never minted is refused the same way, rather than being
    // ignored - ignoring it would silently downgrade an EHR launch to a
    // standalone one, with no patient in context and nobody any the wiser.
    const bogus = await present("not-a-real-handle");
    expect(
      new URL(bogus.headers()["location"] ?? "", ISSUER).searchParams.get(
        "error",
      ),
    ).toBe("invalid_request");
  });
});

test.describe("a confidential client with a shared secret", () => {
  test("completes a launch, refreshes, introspects and revokes", async ({
    page,
    request,
  }) => {
    const code = await authorizeInBrowser(page, {
      clientId: SEED.confidentialClientId,
      scope: "openid fhirUser launch/patient patient/*.rs offline_access",
      patient: "pat-9",
    });
    expect(code).toBeTruthy();

    // ---- The exchange, authenticated with the secret -----------------------
    const exchanged = await request.post(`${ISSUER}/token`, {
      headers: {
        authorization: basic(
          SEED.confidentialClientId,
          SEED.confidentialSecret,
        ),
      },
      form: {
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: VERIFIER,
      },
    });
    expect(exchanged.status()).toBe(200);

    const token = (await exchanged.json()) as Record<string, string>;
    // `offline_access` is granted here and refused to the public client, which is
    // the preset's rule doing its job rather than a difference in the request.
    expect(String(token["scope"])).toContain("offline_access");
    expect(token["refresh_token"]).toBeTruthy();

    // The access token is real: Pathling accepts it.
    const search = await request.get(`${FHIR}/Patient?_count=1`, {
      headers: { authorization: `Bearer ${token["access_token"]}` },
    });
    expect(search.status()).toBe(200);

    // ---- Refresh ------------------------------------------------------------
    const refreshed = await request.post(`${ISSUER}/token`, {
      headers: {
        authorization: basic(
          SEED.confidentialClientId,
          SEED.confidentialSecret,
        ),
      },
      form: {
        grant_type: "refresh_token",
        refresh_token: String(token["refresh_token"]),
      },
    });
    expect(refreshed.status()).toBe(200);

    const rotated = (await refreshed.json()) as Record<string, string>;
    expect(rotated["access_token"]).toBeTruthy();
    // Rotation, not reuse: the old refresh token is replaced.
    expect(rotated["refresh_token"]).not.toBe(token["refresh_token"]);

    // The refreshed token works too. A refresh that returned a token the resource
    // server rejects is a refresh that has not worked.
    const afterRefresh = await request.get(`${FHIR}/Patient?_count=1`, {
      headers: { authorization: `Bearer ${rotated["access_token"]}` },
    });
    expect(afterRefresh.status()).toBe(200);

    // ---- Introspection ------------------------------------------------------
    const introspected = await request.post(`${ISSUER}/introspect`, {
      headers: {
        authorization: basic(
          SEED.confidentialClientId,
          SEED.confidentialSecret,
        ),
      },
      form: { token: String(rotated["access_token"]) },
    });
    expect(introspected.status()).toBe(200);

    const introspection = (await introspected.json()) as Record<
      string,
      unknown
    >;
    expect(introspection["active"]).toBe(true);
    expect(introspection["client_id"]).toBe(SEED.confidentialClientId);
    expect(String(introspection["scope"])).toContain("patient/");

    // ---- Revocation ---------------------------------------------------------
    const revoked = await request.post(`${ISSUER}/revoke`, {
      headers: {
        authorization: basic(
          SEED.confidentialClientId,
          SEED.confidentialSecret,
        ),
      },
      form: { token: String(rotated["access_token"]) },
    });
    // RFC 7009: 200 whether or not the token existed.
    expect(revoked.status()).toBe(200);

    const afterRevocation = await request.post(`${ISSUER}/introspect`, {
      headers: {
        authorization: basic(
          SEED.confidentialClientId,
          SEED.confidentialSecret,
        ),
      },
      form: { token: String(rotated["access_token"]) },
    });
    const revokedState = (await afterRevocation.json()) as Record<
      string,
      unknown
    >;
    expect(revokedState["active"]).toBe(false);

    // What revocation does *not* do, asserted so that nobody deploys Signet
    // believing otherwise. Pathling verifies the JWT locally - signature, `iss`,
    // `aud`, `exp` - and never asks Signet whether the token still lives, so a
    // revoked token keeps opening it until it expires. That is a property of
    // stateless verification rather than a gap in the revocation endpoint, and
    // the control for it is the access token's lifetime, not the revocation call.
    //
    // Revocation is effective immediately for what Signet itself decides:
    // introspection above, and refresh below.
    const stillAccepted = await request.get(`${FHIR}/Patient?_count=1`, {
      headers: { authorization: `Bearer ${rotated["access_token"]}` },
    });
    expect(stillAccepted.status()).toBe(200);

    // Revoking the access token revoked exactly the access token. The refresh
    // token is a separate credential and still works, which is what RFC 7009
    // asks for: the client said "this token", not "this grant".
    const stillRefreshes = await request.post(`${ISSUER}/token`, {
      headers: {
        authorization: basic(
          SEED.confidentialClientId,
          SEED.confidentialSecret,
        ),
      },
      form: {
        grant_type: "refresh_token",
        refresh_token: String(rotated["refresh_token"]),
      },
    });
    expect(stillRefreshes.status()).toBe(200);
    const latest = (await stillRefreshes.json()) as Record<string, string>;

    // Revoking the refresh token is how a client ends the grant, and then there
    // is nothing left to mint with.
    const revokedRefresh = await request.post(`${ISSUER}/revoke`, {
      headers: {
        authorization: basic(
          SEED.confidentialClientId,
          SEED.confidentialSecret,
        ),
      },
      form: {
        token: String(latest["refresh_token"]),
        token_type_hint: "refresh_token",
      },
    });
    expect(revokedRefresh.status()).toBe(200);

    const afterRevokeRefresh = await request.post(`${ISSUER}/token`, {
      headers: {
        authorization: basic(
          SEED.confidentialClientId,
          SEED.confidentialSecret,
        ),
      },
      form: {
        grant_type: "refresh_token",
        refresh_token: String(latest["refresh_token"]),
      },
    });
    expect(afterRevokeRefresh.status()).toBe(400);
  });

  test("revokes the whole family when a spent refresh token is replayed", async ({
    page,
    request,
  }) => {
    const code = await authorizeInBrowser(page, {
      clientId: SEED.reuseClientId,
      scope: "openid fhirUser launch/patient patient/*.rs offline_access",
      patient: "pat-9",
    });

    const first = (await (
      await request.post(`${ISSUER}/token`, {
        headers: {
          authorization: basic(SEED.reuseClientId, SEED.reuseSecret),
        },
        form: {
          grant_type: "authorization_code",
          code,
          redirect_uri: REDIRECT_URI,
          code_verifier: VERIFIER,
        },
      })
    ).json()) as Record<string, string>;

    const rotated = (await (
      await request.post(`${ISSUER}/token`, {
        headers: {
          authorization: basic(SEED.reuseClientId, SEED.reuseSecret),
        },
        form: {
          grant_type: "refresh_token",
          refresh_token: String(first["refresh_token"]),
        },
      })
    ).json()) as Record<string, string>;
    expect(rotated["access_token"]).toBeTruthy();

    // The spent refresh token, presented again. This is what a stolen token looks
    // like once the real client has already rotated.
    const replayed = await request.post(`${ISSUER}/token`, {
      headers: {
        authorization: basic(SEED.reuseClientId, SEED.reuseSecret),
      },
      form: {
        grant_type: "refresh_token",
        refresh_token: String(first["refresh_token"]),
      },
    });
    expect(replayed.status()).toBe(400);

    // Refusing the replay is not enough on its own: at that point Signet knows
    // one of the two holders is an attacker but not which, so the whole family
    // goes. Introspection is where that is observable, because it is Signet
    // answering rather than a resource server verifying a signature.
    const introspected = await request.post(`${ISSUER}/introspect`, {
      headers: {
        authorization: basic(SEED.reuseClientId, SEED.reuseSecret),
      },
      form: { token: String(rotated["access_token"]) },
    });
    const state = (await introspected.json()) as Record<string, unknown>;
    expect(state["active"]).toBe(false);

    // And the rotated refresh token is dead with the rest of its family.
    const rotatedAgain = await request.post(`${ISSUER}/token`, {
      headers: {
        authorization: basic(SEED.reuseClientId, SEED.reuseSecret),
      },
      form: {
        grant_type: "refresh_token",
        refresh_token: String(rotated["refresh_token"]),
      },
    });
    expect(rotatedAgain.status()).toBe(400);
  });

  test("is refused an exchange without its secret", async ({ request }) => {
    // No browser flow, and deliberately so. The client is refused for want of a
    // credential before the code is ever looked at, so an unauthenticated request
    // carrying a code that could not work still has to come back 401 rather than
    // `invalid_grant` - a 400 here would say the credential was accepted and the
    // code rejected, which is the opposite of the order that keeps a confidential
    // client confidential.
    //
    // Writing it this way also keeps the suite under the sign-in rate limit; see
    // `tests/auth.setup.ts` for why that matters.
    const response = await request.post(`${ISSUER}/token`, {
      form: {
        grant_type: "authorization_code",
        code: "not-a-real-code",
        redirect_uri: REDIRECT_URI,
        code_verifier: VERIFIER,
        client_id: SEED.confidentialClientId,
      },
    });
    expect(response.status()).toBe(401);
  });
});

test.describe("a confidential client with a signing key", () => {
  test("authenticates with private_key_jwt and Pathling accepts the token", async ({
    request,
  }) => {
    const response = await tokenWithAssertion(request, "system/Patient.rs");
    expect(response.status()).toBe(200);

    const body = (await response.json()) as Record<string, string>;
    expect(body["scope"]).toBe("system/Patient.rs");

    const search = await request.get(`${FHIR}/Patient?_count=1`, {
      headers: { authorization: `Bearer ${body["access_token"]}` },
    });
    expect(search.status()).toBe(200);
  });

  test("is refused an assertion signed by the wrong key", async ({
    request,
  }) => {
    // A well-formed assertion whose signature does not verify against the
    // registered JWKS. It even carries the registered `kid`, so what is being
    // asserted is the signature check rather than key selection.
    const key = await importJWK({ ...WRONG_KEY, alg: "ES384" }, "ES384");
    const assertion = await new SignJWT({})
      .setProtectedHeader({ alg: "ES384", kid: ASYMMETRIC_KID })
      .setIssuer(SEED.asymmetricClientId)
      .setSubject(SEED.asymmetricClientId)
      .setAudience(`${ISSUER}/token`)
      .setJti(crypto.randomUUID())
      .setIssuedAt()
      .setExpirationTime("2m")
      .sign(key);

    const response = await request.post(`${ISSUER}/token`, {
      form: {
        grant_type: "client_credentials",
        scope: "system/Patient.rs",
        client_assertion_type:
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: assertion,
      },
    });
    expect(response.status()).toBe(401);
  });

  test("refuses the same assertion twice", async ({ request }) => {
    const assertion = await clientAssertion(`${ISSUER}/token`);
    const form = {
      grant_type: "client_credentials",
      scope: "system/Patient.rs",
      client_assertion_type:
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: assertion,
    };

    expect((await request.post(`${ISSUER}/token`, { form })).status()).toBe(
      200,
    );

    // The `jti` has been seen. Replaying a captured assertion within its lifetime
    // is the attack this closes.
    expect((await request.post(`${ISSUER}/token`, { form })).status()).toBe(
      401,
    );
  });
});

/** A second, unregistered P-384 key pair, for the wrong-key test. */
const WRONG_KEY = {
  kty: "EC",
  crv: "P-384",
  x: "aawPtgMXCReyGu1VxOSzMx1oOAOvSn9qwtrfF_-f2Hjdv2WuFC3OLeyndGLiUM5M",
  y: "cX1mROB_F1rD79cF-Dt0Se_xHEfKLf4pN4sVqqUeQMYLvJbe6P4Q7RRRfwu_x_pX",
  d: "qKgOm4EN80GO9M_g3NSs9iZz9qwo1RAz-RNyfiUryCCRPcG5XcN_Mt8_XIjOGkUC",
} as const;

/**
 * Requests a token as the asymmetric client.
 *
 * @param request - Playwright's request context.
 * @param scope - The scope to ask for.
 * @returns The raw response, so a test can assert on its status.
 */
async function tokenWithAssertion(
  request: APIRequestContext,
  scope: string,
): Promise<Awaited<ReturnType<APIRequestContext["post"]>>> {
  return await request.post(`${ISSUER}/token`, {
    form: {
      grant_type: "client_credentials",
      scope,
      client_assertion_type:
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: await clientAssertion(`${ISSUER}/token`),
    },
  });
}
