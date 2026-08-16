/**
 * The two capabilities an endpoint refuses until somebody names an issuer.
 *
 * Both are opt-in per endpoint and both are off here until this file turns them
 * on, which is what the first test asserts and what the last test restores. That
 * shape is not decoration: an endpoint with no trust anchor must be
 * indistinguishable from a build with no registration endpoint, and the only way
 * to show it is to look before configuring anything.
 *
 * What is proved here and nowhere else in the repository:
 *
 * - A client that no human approved - created from a statement an anchor signed,
 *   over HTTP, at the address the endpoint advertised - completes a real SMART
 *   launch in a real browser and comes back with a token the real Pathling
 *   accepts. The integration suites prove the registration; only this proves the
 *   client it produced is a client.
 * - A permission ticket exchanged by an authenticated client yields a token whose
 *   patient context Pathling serves, and whose scope stops at the intersection:
 *   the resource type the ticket permitted answers 200 and the one it did not is
 *   refused *by Pathling*, from the authorities Signet put in the token.
 *
 * **Serial, and it has to be.** The three tests share one endpoint's configuration
 * and the first of them asserts the absence of what the second creates. Playwright
 * runs a file's tests in parallel by default, which would have them racing over
 * one row.
 *
 * **The sign-in budget.** This file spends one end-user sign-in, in the launch
 * below. See `playwright.config.ts` for the ten a minute that are going.
 *
 * The anchor is the same stand-in the unit and integration suites use, addressed so
 * that Signet-in-a-container can fetch its keys: `../support/trustAnchor.ts`.
 *
 * Author: John Grimes
 */

import { expect, request as apiRequest, test } from "@playwright/test";

import {
  DEFAULT_SUBJECT_SYSTEM,
  DEFAULT_SUBJECT_VALUE,
} from "../../apps/server/src/test/trustAnchor.js";
import { completeStandaloneLaunch } from "../support/launch.js";
import {
  APP,
  CONSOLE_STORAGE_STATE,
  FHIR,
  ISSUER,
  SEED,
  SIGNET,
} from "../support/stack.js";
import { startStackTrustAnchor } from "../support/trustAnchor.js";

import type { TrustAnchor } from "../../apps/server/src/test/trustAnchor.js";
import type { APIRequestContext } from "@playwright/test";

/** The endpoint's trust rules, as the console configures them. */
const TRUST = `${SIGNET}/api/v1/tenants/demo/endpoints/pathling/trust`;

/** The scopes the vouched client is registered for, and launches with. */
const VOUCHED_SCOPE = "openid fhirUser launch/patient patient/*.rs";

/** The ticket type the connectathon programme exercises. */
const TICKET_TYPE = "patient-self-access";

// RFC 8693's URNs, written out rather than imported from the module under test.
// What an app sends is the string, and a test that reused Signet's own constant
// would keep passing if the constant changed to something no client sends.
const EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

/** The endpoint's SMART configuration, as an app discovers it. */
async function smartConfiguration(
  request: APIRequestContext,
): Promise<Record<string, unknown>> {
  const response = await request.get(
    `${ISSUER}/.well-known/smart-configuration`,
  );
  expect(response.ok()).toBe(true);
  return (await response.json()) as Record<string, unknown>;
}

/** HTTP Basic, as a confidential client presents it at the token endpoint. */
function basicAuthorization(clientId: string, secret: string): string {
  return `Basic ${Buffer.from(`${clientId}:${secret}`).toString("base64")}`;
}

/** Posts a token-exchange request carrying a permission ticket. */
async function exchangeTicket(
  request: APIRequestContext,
  ticket: string,
  scope: string,
): Promise<Awaited<ReturnType<APIRequestContext["post"]>>> {
  return await request.post(`${ISSUER}/token`, {
    headers: {
      authorization: basicAuthorization(
        SEED.confidentialClientId,
        SEED.confidentialSecret,
      ),
    },
    form: {
      grant_type: EXCHANGE_GRANT_TYPE,
      subject_token: ticket,
      subject_token_type: JWT_TOKEN_TYPE,
      scope,
    },
  });
}

test.describe.serial("an endpoint's trust rules", () => {
  let anchor: TrustAnchor;
  let admin: APIRequestContext;

  test.beforeAll(async () => {
    anchor = await startStackTrustAnchor();
    // A context of its own rather than `test.use`, so that the browser the launch
    // runs in carries no console session. A launch is a thing an app's user does,
    // and one driven from an operator's browser would be a different journey.
    admin = await apiRequest.newContext({
      storageState: CONSOLE_STORAGE_STATE,
    });
  });

  test.afterAll(async () => {
    // Back to refusing, so a second run of this suite finds the posture the first
    // test asserts. Both are tolerated when absent: the first test may have been
    // the one that failed.
    await admin.delete(`${TRUST}/anchor`);
    await admin.delete(`${TRUST}/ticket-issuer`);
    await admin.dispose();
    await anchor.close();
  });

  test("refuse registration and ticket exchange until an issuer is named", async ({
    request,
  }) => {
    // Removed rather than assumed absent. The suite is expected to run against a
    // stack it did not create, including one a previous run configured and failed
    // half way through, and an assertion that only holds on a pristine stack is an
    // assertion that will one day be deleted for flaking.
    await admin.delete(`${TRUST}/anchor`);
    await admin.delete(`${TRUST}/ticket-issuer`);

    const registration = await request.post(`${ISSUER}/register`, {
      data: { software_statement: "not.even.looked.at" },
    });
    // 404, not 403: an endpoint that has not opted in must look like a build where
    // this route does not exist. A refusal that admits the route is there tells an
    // attacker which endpoints to come back to.
    expect(registration.status()).toBe(404);

    const configuration = await smartConfiguration(request);
    expect(configuration["registration_endpoint"]).toBeUndefined();
    expect(
      configuration["smart_permission_ticket_types_supported"],
    ).toBeUndefined();

    const exchanged = await exchangeTicket(
      request,
      "not.even.looked.at",
      "patient/Patient.rs",
    );
    expect(exchanged.status()).toBe(400);
    expect(await exchanged.json()).toMatchObject({
      error: "unsupported_grant_type",
    });
  });

  test("register a client the anchor vouched for, which then completes a launch", async ({
    browser,
    page,
    request,
  }) => {
    const configured = await admin.put(`${TRUST}/anchor`, {
      data: {
        issuer: anchor.issuer,
        jwksUri: anchor.jwksUri,
        maxVouchingDays: 30,
      },
    });
    expect(configured.status()).toBe(200);

    // The console's own check, before anything relies on it. It fetches the
    // published keys through the resolver the registration will use, so a stack
    // where Signet cannot reach the anchor fails here - naming the network - rather
    // than as an `invalid_software_statement` that reads like a bad statement.
    const checked = await admin.post(`${TRUST}/anchor/check`);
    expect(await checked.json()).toMatchObject({
      ok: true,
      keyIds: [anchor.keyId],
    });

    // Now, and only now, the endpoint advertises where to register.
    const configuration = await smartConfiguration(request);
    expect(configuration["registration_endpoint"]).toBe(`${ISSUER}/register`);

    const statement = await anchor.mintStatement({
      claims: {
        client_name: `Vouched stub app ${String(Date.now())}`,
        // The stub app's own address, so the client this creates is one that can
        // actually be launched. A registration whose redirect URI nothing serves
        // would register perfectly and prove nothing.
        redirect_uris: [`${APP}/`],
        grant_types: ["authorization_code"],
        token_endpoint_auth_method: "none",
        scope: VOUCHED_SCOPE,
      },
      lifetimeSeconds: 3600,
    });

    const registered = await request.post(`${ISSUER}/register`, {
      data: { software_statement: statement },
    });
    expect(registered.status()).toBe(201);

    const created = (await registered.json()) as Record<string, unknown>;
    const clientId = String(created["client_id"]);
    expect(clientId).toBeTruthy();
    // The statement's metadata, and only the statement's.
    expect(created["redirect_uris"]).toEqual([`${APP}/`]);
    expect(created["token_endpoint_auth_method"]).toBe("none");
    // A public client is issued no secret, and nothing else here is either.
    expect(created["client_secret"]).toBeUndefined();

    // ---- The launch, in the browser, as the app's user ----------------------
    await page.goto(
      `${APP}/?iss=${encodeURIComponent(ISSUER)}&aud=${encodeURIComponent(FHIR)}&client_id=${encodeURIComponent(clientId)}&scope=${encodeURIComponent(VOUCHED_SCOPE)}`,
    );
    const tokenResponse = await completeStandaloneLaunch(page, "pat-9");
    expect(tokenResponse["patient"]).toBe("pat-9");
    expect(String(tokenResponse["scope"])).toContain("patient/");

    // And Pathling accepts what the vouched client was given. This is the whole
    // claim of the story: no human approved this client, and the resource server
    // cannot tell it from one that a human did.
    await expect(page.getByTestId("fhir-status")).toContainText(
      "answered 200",
      {
        timeout: 20_000,
      },
    );

    // ---- What the console shows about it ------------------------------------
    // A context rather than the page above, which is mid-launch and holds no
    // console session.
    const operator = await browser.newContext({
      storageState: CONSOLE_STORAGE_STATE,
    });
    const detail = await operator.newPage();
    await detail.goto(
      `${SIGNET}/console/t/demo/e/pathling/clients/${clientId}`,
    );
    // Who vouched, and until when. An operator looking at a client they did not
    // create has to be able to see where it came from, which is the one thing a
    // vouched client needs that a portal-created one does not.
    await expect(
      detail.getByRole("heading", { name: "Vouching" }),
    ).toBeVisible();
    await expect(
      detail.getByText(anchor.issuer, { exact: true }),
    ).toBeVisible();
    await expect(detail.getByText("remaining")).toBeVisible();
    await operator.close();
  });

  test("exchange a permission ticket for a token bounded by what the ticket permits", async ({
    request,
  }) => {
    const configured = await admin.put(`${TRUST}/ticket-issuer`, {
      data: {
        issuer: anchor.issuer,
        jwksUri: anchor.jwksUri,
        acceptedTicketTypes: [TICKET_TYPE],
        maxTokenLifetimeSecs: 300,
      },
    });
    expect(configured.status()).toBe(200);

    const configuration = await smartConfiguration(request);
    expect(configuration["smart_permission_ticket_types_supported"]).toEqual([
      TICKET_TYPE,
    ]);

    // The ticket permits one resource type. The request asks for two, and the
    // client's registration allows both, so the only thing that can narrow the
    // result to one is the ticket.
    const ticket = await anchor.mintTicket({
      claims: {
        ticket_type: TICKET_TYPE,
        subject: {
          system: DEFAULT_SUBJECT_SYSTEM,
          value: DEFAULT_SUBJECT_VALUE,
        },
        smart_scopes: ["patient/Patient.rs"],
      },
    });

    const exchanged = await exchangeTicket(
      request,
      ticket,
      "patient/Patient.rs patient/Observation.rs",
    );
    expect(exchanged.status()).toBe(200);

    const token = (await exchanged.json()) as Record<string, unknown>;
    expect(token["scope"]).toBe("patient/Patient.rs");
    // Resolved from the ticket's IHI by searching Pathling, not read out of the
    // ticket: the ticket names a person, and only the FHIR server knows which
    // record that is here.
    expect(token["patient"]).toBe(SEED.ticketSubjectPatientId);
    expect(token["issued_token_type"]).toBe(ACCESS_TOKEN_TYPE);
    // A ticket authorises one piece of work. Handing back a refresh token would
    // turn it into a standing grant nobody reviewed.
    expect(token["refresh_token"]).toBeUndefined();
    expect(Number(token["expires_in"])).toBeLessThanOrEqual(300);

    const accessToken = String(token["access_token"]);

    // ---- What the token opens ------------------------------------------------
    const read = await request.get(
      `${FHIR}/Patient/${SEED.ticketSubjectPatientId}`,
      { headers: { authorization: `Bearer ${accessToken}` } },
    );
    expect(read.status()).toBe(200);
    expect(JSON.stringify(await read.json())).toContain(DEFAULT_SUBJECT_VALUE);

    // ---- And what it does not -----------------------------------------------
    // Refused by Pathling, from the authorities Signet did not put in the token.
    // Asserting the granted `scope` string alone would pass on a build that
    // translated the scope into an authority nobody asked for.
    const outOfScope = await request.get(`${FHIR}/Observation?_count=1`, {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(outOfScope.status()).toBe(403);
  });
});
