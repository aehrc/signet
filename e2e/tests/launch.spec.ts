/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { expect, test } from "@playwright/test";

import {
  accessTokenClaims,
  choosePatient,
  completeStandaloneLaunch,
  decideConsent,
  signIn,
  startLaunch,
} from "../support/launch.js";
import { FHIR, ISSUER, SEED } from "../support/stack.js";

/**
 * A SMART app launching against Signet, in a browser, end to end.
 *
 * This is the suite the whole stack exists for. Everything else in the repository
 * tests a part; this asserts the property that matters to somebody deploying it:
 * an app that follows SMART App Launch gets a token, and the FHIR server behind
 * Signet accepts that token.
 *
 * It is driven through the stub app rather than by calling the endpoints, because
 * a launch is a sequence of browser navigations and redirects. A test that posted
 * to `/token` directly would pass on a build where the redirect back to the app
 * was broken.
 */

test.describe("a standalone launch", () => {
  test("gets a token the FHIR server accepts", async ({ page }) => {
    await startLaunch(page);

    // Back at the app, with a token.
    const tokenResponse = await completeStandaloneLaunch(page, "pat-9");
    expect(tokenResponse["token_type"]).toBe("Bearer");
    expect(tokenResponse["patient"]).toBe("pat-9");
    expect(String(tokenResponse["scope"])).toContain("patient/");
    // No refresh token, and that is the policy working rather than a gap: the
    // Pathling preset grants `offline_access` to confidential clients only, so a
    // public app asking for it is granted everything else and told what it got.
    expect(String(tokenResponse["scope"])).not.toContain("offline_access");
    expect(tokenResponse["refresh_token"]).toBeUndefined();

    const claims = await accessTokenClaims(page);
    expect(claims["iss"]).toBe(ISSUER);
    expect(claims["aud"]).toBe(FHIR);
    expect(claims["fhirUser"]).toBe("Practitioner/clinician-1");
    // The whole point of the Pathling preset: SMART scopes in, Pathling's own
    // authorities out. Asserted in full rather than by `arrayContaining`, because
    // the hyphenated operation authorities are the ones a Pathling older than
    // 3.0.0 cannot parse - and it does not ignore what it cannot parse, it fails
    // the whole request. A containment check would let that regression through.
    expect(claims["authorities"]).toEqual([
      "pathling:read",
      "pathling:search",
      "pathling:read-resource",
      "pathling:export",
      "pathling:sql-run",
      "pathling:sql-export",
      "pathling:jobs",
    ]);

    // And the token works. Nothing else in this repository can assert that.
    await expect(page.getByTestId("fhir-status")).toContainText(
      "answered 200",
      {
        timeout: 20_000,
      },
    );
  });

  test("ends at the app with access_denied when the user declines", async ({
    page,
  }) => {
    await startLaunch(page);
    await signIn(page);
    await choosePatient(page, "pat-9");
    await decideConsent(page, "Deny");

    // Back at the app with a refusal rather than a code: the person said no, and
    // the app is told so in the way OAuth specifies.
    await expect(page.getByTestId("status")).toContainText("access_denied", {
      timeout: 20_000,
    });
  });

  test("refuses a wrong password without saying which part was wrong", async ({
    page,
  }) => {
    await startLaunch(page);
    await signIn(page, {
      username: SEED.username,
      password: "not the password",
    });

    const alert = page.getByRole("alert");
    await expect(alert).toBeVisible();
    // One message for every credential failure. A page that distinguished
    // "no such user" from "wrong password" would be a user enumeration oracle
    // with a nicer interface.
    await expect(alert).toContainText(/not accepted/i);

    await signIn(page, {
      username: "nobody-at-all",
      password: "not the password",
    });
    await expect(page.getByRole("alert")).toContainText(/not accepted/i);
  });
});

test.describe("the discovery documents", () => {
  test("are what Pathling merges its own configuration from", async ({
    request,
  }) => {
    const merged = await request.get(`${FHIR}/.well-known/smart-configuration`);
    expect(merged.ok()).toBe(true);

    const body = (await merged.json()) as Record<string, unknown>;
    // Pathling assembles this by merging fields out of Signet's OpenID Connect
    // document. If it names Signet's endpoints, the integration an operator has
    // to perform really is one environment variable.
    expect(body["issuer"]).toBe(ISSUER);
    expect(body["authorization_endpoint"]).toBe(`${ISSUER}/authorize`);
    expect(body["token_endpoint"]).toBe(`${ISSUER}/token`);
  });

  test("advertise only algorithms the JWKS publishes", async ({ request }) => {
    const configuration = (await (
      await request.get(`${ISSUER}/.well-known/openid-configuration`)
    ).json()) as { id_token_signing_alg_values_supported: string[] };
    const jwks = (await (await request.get(`${ISSUER}/jwks`)).json()) as {
      keys: { alg?: string }[];
    };

    const published = new Set(jwks.keys.map((key) => key.alg));
    for (const advertised of configuration.id_token_signing_alg_values_supported) {
      // A verifier configured from this document must accept what the endpoint
      // signs with. Advertising an algorithm no key uses is how a Spring-based
      // resource server ends up rejecting every token.
      expect(published).toContain(advertised);
    }
  });
});

test.describe("backend services", () => {
  test("mints a token for a client credentials grant and Pathling accepts it", async ({
    request,
  }) => {
    const response = await request.post(`${ISSUER}/token`, {
      form: {
        grant_type: "client_credentials",
        scope: "system/Patient.rs",
      },
      headers: {
        authorization: `Basic ${Buffer.from(
          `${SEED.backendClientId}:${SEED.backendSecret}`,
        ).toString("base64")}`,
      },
    });
    expect(response.status()).toBe(200);

    const body = (await response.json()) as Record<string, unknown>;
    expect(body["scope"]).toBe("system/Patient.rs");
    // No refresh token for a backend service: it holds a credential and can ask
    // again, so a refresh token would be a second credential for no benefit.
    expect(body["refresh_token"]).toBeUndefined();

    const search = await request.get(`${FHIR}/Patient?_count=1`, {
      headers: { authorization: `Bearer ${String(body["access_token"])}` },
    });
    expect(search.status()).toBe(200);
  });

  test("is refused a scope the client is not allowed", async ({ request }) => {
    const response = await request.post(`${ISSUER}/token`, {
      form: { grant_type: "client_credentials", scope: "system/*.cud" },
      headers: {
        authorization: `Basic ${Buffer.from(
          `${SEED.backendClientId}:${SEED.backendSecret}`,
        ).toString("base64")}`,
      },
    });
    expect(response.status()).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_scope" });
  });

  test("refuses a wrong client secret", async ({ request }) => {
    const response = await request.post(`${ISSUER}/token`, {
      form: { grant_type: "client_credentials", scope: "system/Patient.rs" },
      headers: {
        authorization: `Basic ${Buffer.from(
          `${SEED.backendClientId}:not-the-secret`,
        ).toString("base64")}`,
      },
    });
    expect(response.status()).toBe(401);
    expect(response.headers()["www-authenticate"]).toContain("Basic");
  });
});
