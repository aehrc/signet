/**
 * Permission ticket exchange, against a real database, issuer and FHIR server.
 *
 * The suite's spine is the pair of postures, as the registration suite's is. An
 * endpoint with no ticket issuer rule refuses the grant type outright and
 * advertises no ticket support; an endpoint with one accepts that issuer's
 * tickets and nobody else's. Everything in between is a refusal, and a refusal is
 * only evidence if the fixture failed for the reason the test names - so the
 * tickets are minted by `../test/trustAnchor.ts`, where an expired ticket carries
 * a perfectly good signature and a tampered one still decodes.
 *
 * The endpoint's `aud` is a FHIR stub on a loopback socket, because subject
 * resolution is a real search against it: the ticket names an IHI and the token
 * carries a patient, and the only thing that joins them is one query whose answer
 * must be exactly one patient. The stub also records the credential Signet
 * presented, which is how "a self-issued system token" is checked rather than
 * assumed.
 *
 * Both the issuer and the FHIR stub bind loopback, so the stack is built with
 * `allowPrivateOutboundFetches`.
 *
 * Author: John Grimes
 */

import {
  ACCESS_TOKEN_TYPE,
  JWT_SUBJECT_TOKEN_TYPE,
  TOKEN_EXCHANGE_GRANT_TYPE,
} from "@signet/core";
import {
  deleteEndpointTicketIssuer,
  queryAuditEvents,
  upsertEndpointTicketIssuer,
  withTenantScope,
} from "@signet/db";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
} from "bun:test";

import {
  authorizeToCode,
  basicAuth,
  decodePayload,
  issuerPath,
  postForm,
} from "../test/flows.js";
import {
  createTestStack,
  TEST_CLIENT_SECRET,
  testDatabaseUrl,
} from "../test/harness.js";
import { jsonResponse, startLocalListener } from "../test/localListener.js";
import { startTrustAnchor, tamperJws } from "../test/trustAnchor.js";

import type { TestStack } from "../test/harness.js";
import type { LocalListener } from "../test/localListener.js";
import type { TrustAnchor } from "../test/trustAnchor.js";

const describeWithDatabase =
  testDatabaseUrl === undefined ? describe.skip : describe;

/** The identifier system the programme's tickets name their subject in. */
const IHI_SYSTEM = "http://ns.electronichealth.net.au/id/hi/ihi/1.0";

/** The IHI the FHIR stub's patient carries. */
const IHI_VALUE = "8003608500314687";

/** The patient the stub resolves that IHI to. */
const PATIENT_ID = "pat-1";

/** The rule's cap, deliberately below the endpoint's own token lifetime. */
const RULE_MAX_LIFETIME = 120;

/** A token response or a refusal, as an app would read it. */
interface ExchangeResponse {
  readonly access_token?: string;
  readonly token_type?: string;
  readonly expires_in?: number;
  readonly scope?: string;
  readonly refresh_token?: string;
  readonly issued_token_type?: string;
  readonly patient?: string;
  readonly error?: string;
  readonly error_description?: string;
}

/** What the FHIR stub was asked, and with what credential. */
interface FhirRequest {
  readonly pathname: string;
  readonly identifier: string | null;
  readonly authorization: string | null;
}

describeWithDatabase("permission ticket exchange", () => {
  let stack: TestStack;
  let issuer: TrustAnchor;
  let fhir: LocalListener;
  let served: FhirRequest[] = [];
  /** How many patients the stub reports for a matching identifier. */
  let matchCount = 1;
  /** Set to answer the search with a failure instead of a bundle. */
  let searchStatus: number | undefined;

  beforeAll(async () => {
    issuer = await startTrustAnchor();
    fhir = await startLocalListener(async (request) => {
      const url = new URL(request.url);
      served.push({
        pathname: url.pathname,
        identifier: url.searchParams.get("identifier"),
        authorization: request.headers.get("authorization"),
      });
      if (searchStatus !== undefined) {
        return await Promise.resolve(
          jsonResponse({ resourceType: "OperationOutcome" }, searchStatus),
        );
      }
      const matched =
        url.searchParams.get("identifier") === `${IHI_SYSTEM}|${IHI_VALUE}`;
      return await Promise.resolve(
        jsonResponse({
          resourceType: "Bundle",
          type: "searchset",
          entry: matched
            ? Array.from({ length: matchCount }, (_, index) => ({
                resource: {
                  resourceType: "Patient",
                  id: index === 0 ? PATIENT_ID : `pat-${String(index + 1)}`,
                },
              }))
            : [],
        }),
      );
    });

    stack = await createTestStack({
      allowPrivateOutboundFetches: true,
      endpoint: { fhirBaseUrl: `${fhir.origin}/fhir` },
    });
    // A whole second, so that a lifetime asserted exactly is exactly what a
    // ticket minted at this instant leaves. The grant floors the remaining
    // validity - never rounds up, which would issue a token outliving its
    // ticket - and a clock carrying milliseconds would make every assertion here
    // one second short for reasons that have nothing to do with the capping.
    stack.setNow(new Date(Math.floor(Date.now() / 1000) * 1000));
  });

  afterAll(async () => {
    await stack.close();
    await issuer.close();
    await fhir.close();
  });

  /** Points the endpoint's ticket issuer rule at the fixture issuer. */
  async function configureIssuer(
    overrides: {
      readonly acceptedTicketTypes?: readonly string[];
      readonly maxTokenLifetimeSecs?: number;
    } = {},
  ): Promise<void> {
    await withTenantScope(stack.context.db, stack.scope, (bound) =>
      upsertEndpointTicketIssuer(bound, {
        issuer: issuer.issuer,
        jwksUri: issuer.jwksUri,
        acceptedTicketTypes: [
          ...(overrides.acceptedTicketTypes ?? ["patient-self-access"]),
        ],
        maxTokenLifetimeSecs:
          overrides.maxTokenLifetimeSecs ?? RULE_MAX_LIFETIME,
      }),
    );
  }

  /** Removes the rule, returning the endpoint to refusing the grant type. */
  async function removeIssuer(): Promise<boolean> {
    return await withTenantScope(stack.context.db, stack.scope, (bound) =>
      deleteEndpointTicketIssuer(bound),
    );
  }

  /** Mints a ticket at the stack's clock, with the case's overrides. */
  async function mintTicket(
    options: Parameters<TrustAnchor["mintTicket"]>[0] = {},
  ): Promise<string> {
    return await issuer.mintTicket({
      issuedAt: stack.context.clock(),
      ...options,
    });
  }

  /** The header the confidential fixture client authenticates with. */
  function symmetricCredential(): Readonly<Record<string, string>> {
    return { authorization: basicAuth(stack.symmetricClient.clientId) };
  }

  /** Posts an exchange, by default as the confidential fixture client. */
  async function exchange(
    fields: Readonly<Record<string, string>>,
    credential: Readonly<Record<string, string>> = symmetricCredential(),
  ): Promise<{ status: number; body: ExchangeResponse }> {
    const response = await postForm(
      stack,
      "/token",
      { grant_type: TOKEN_EXCHANGE_GRANT_TYPE, ...fields },
      credential,
    );
    return {
      status: response.status,
      body: (await response.json()) as ExchangeResponse,
    };
  }

  /** Exchanges a freshly minted ticket, with the case's overrides. */
  async function exchangeTicket(
    options: {
      readonly ticket?: Parameters<TrustAnchor["mintTicket"]>[0];
      readonly scope?: string;
      readonly subjectToken?: string;
      readonly subjectTokenType?: string;
      readonly credential?: Readonly<Record<string, string>>;
    } = {},
  ) {
    const subjectToken =
      options.subjectToken ?? (await mintTicket(options.ticket));
    return await exchange(
      {
        subject_token: subjectToken,
        subject_token_type: options.subjectTokenType ?? JWT_SUBJECT_TOKEN_TYPE,
        scope: options.scope ?? "patient/Patient.rs patient/Observation.rs",
      },
      options.credential ?? symmetricCredential(),
    );
  }

  /** The endpoint's SMART configuration, as an app would read it. */
  async function smartConfiguration(): Promise<Record<string, unknown>> {
    const response = await stack.app.request(
      `${issuerPath(stack)}/.well-known/smart-configuration`,
    );
    return (await response.json()) as Record<string, unknown>;
  }

  /** The endpoint's audit events for one action, most recent first. */
  async function auditEvents(action: "token.ticket-exchanged") {
    const page = await withTenantScope(
      stack.context.db,
      stack.tenantScope,
      (bound) => queryAuditEvents(bound, { actions: [action], limit: 50 }),
    );
    return page.events;
  }

  beforeEach(async () => {
    served = [];
    matchCount = 1;
    searchStatus = undefined;
    await configureIssuer();
  });

  describe("without a ticket issuer rule", () => {
    it("refuses the grant type outright", async () => {
      await removeIssuer();

      const refused = await exchangeTicket();
      expect(refused.status).toBe(400);
      expect(refused.body.error).toBe("unsupported_grant_type");
      expect(refused.body.access_token).toBeUndefined();
    });

    it("advertises no supported ticket types", async () => {
      await removeIssuer();

      const document = await smartConfiguration();
      expect(Object.keys(document)).not.toContain(
        "smart_permission_ticket_types_supported",
      );
    });

    it("never reaches the FHIR server to resolve a subject", async () => {
      // The rule gate is the first thing the grant does. An endpoint that has
      // not opted in must not be made to search its own FHIR server by anybody
      // who can post a ticket at it.
      await removeIssuer();

      await exchangeTicket();
      expect(served).toHaveLength(0);
    });
  });

  describe("with a ticket issuer rule", () => {
    it("advertises the ticket types it accepts", async () => {
      const document = await smartConfiguration();
      expect(document["smart_permission_ticket_types_supported"]).toEqual([
        "patient-self-access",
      ]);
    });

    it("grants the intersection of the request, the ticket and the policy", async () => {
      // The app asks for two scopes and the ticket permits one. What it gets is
      // the overlap - never the union, and never a scopeless token.
      const exchanged = await exchangeTicket();

      expect(exchanged.status).toBe(200);
      expect(exchanged.body.scope).toBe("patient/Patient.rs");
      expect(exchanged.body.token_type).toBe("Bearer");
      expect(exchanged.body.issued_token_type).toBe(ACCESS_TOKEN_TYPE);

      const claims = decodePayload(exchanged.body.access_token ?? "");
      expect(claims["scope"]).toBe("patient/Patient.rs");
      expect(claims["aud"]).toBe(stack.endpoint.fhirBaseUrl);
      expect(claims["iss"]).toBe(stack.issuer);
      expect(claims["client_id"]).toBe(stack.symmetricClient.clientId);
    });

    it("resolves the ticket's subject to the patient in the token's context", async () => {
      const exchanged = await exchangeTicket();

      expect(exchanged.body.patient).toBe(PATIENT_ID);
      // One search, against the endpoint's own audience, for the ticket's
      // identifier as a system-and-value token.
      const search = served.find((request) => request.identifier !== null);
      expect(search?.pathname).toBe("/fhir/Patient");
      expect(search?.identifier).toBe(`${IHI_SYSTEM}|${IHI_VALUE}`);
    });

    it("authenticates the search with a system token this endpoint issued", async () => {
      // Signet eats its own dog food rather than needing a side-door credential:
      // the search carries a token signed by the endpoint, scoped by the
      // endpoint's own policy to reading patients.
      await exchangeTicket();

      const search = served.find((request) => request.identifier !== null);
      const presented = (search?.authorization ?? "").replace(/^Bearer /u, "");
      const claims = decodePayload(presented);
      expect(claims["iss"]).toBe(stack.issuer);
      expect(claims["aud"]).toBe(stack.endpoint.fhirBaseUrl);
      expect(String(claims["scope"])).toContain("system/Patient.rs");
      // Short-lived: it exists for one search.
      expect(Number(claims["exp"]) - Number(claims["iat"])).toBeLessThanOrEqual(
        60,
      );
    });

    it("issues a token whose claims match an equivalent interactive launch", async () => {
      // The whole promise of the grant: a resource server cannot tell an
      // exchanged token from one a patient obtained by launching the app, other
      // than by who its subject is.
      const exchanged = await exchangeTicket({ scope: "patient/Patient.rs" });
      const { code, verifier } = await authorizeToCode(stack, {
        clientId: stack.symmetricClient.clientId,
        scope: "patient/Patient.rs",
        patient: PATIENT_ID,
      });
      const redeemed = await postForm(
        stack,
        "/token",
        {
          grant_type: "authorization_code",
          code,
          redirect_uri: "https://app.test/cb",
          code_verifier: verifier,
        },
        { authorization: basicAuth(stack.symmetricClient.clientId) },
      );
      const interactive = (await redeemed.json()) as ExchangeResponse;

      expect(redeemed.status).toBe(200);
      expect(exchanged.body.patient).toBe(interactive.patient ?? "");
      expect(exchanged.body.scope).toBe(interactive.scope ?? "");

      const exchangedClaims = decodePayload(exchanged.body.access_token ?? "");
      const interactiveClaims = decodePayload(interactive.access_token ?? "");
      for (const claim of ["iss", "aud", "scope", "client_id"]) {
        expect(exchangedClaims[claim]).toEqual(interactiveClaims[claim]);
      }
      // The subject is the one thing that differs, and it must: the ticket
      // names a patient rather than a signed-in user.
      expect(exchangedClaims["sub"]).toBe(`Patient/${PATIENT_ID}`);
    });

    it("issues no refresh token, whatever the ticket and the request ask for", async () => {
      const exchanged = await exchangeTicket({
        ticket: {
          claims: { smart_scopes: ["patient/Patient.rs", "offline_access"] },
        },
        scope: "patient/Patient.rs offline_access",
      });

      expect(exchanged.status).toBe(200);
      expect(exchanged.body.refresh_token).toBeUndefined();
      expect(exchanged.body.scope).toBe("patient/Patient.rs");
    });

    it("caps the token's lifetime at the rule's maximum", async () => {
      // Three ceilings: the ticket's remaining validity, the endpoint's own
      // token lifetime, and the rule's. Here the rule's is the smallest.
      const exchanged = await exchangeTicket({
        ticket: { lifetimeSeconds: 3000 },
      });
      expect(exchanged.body.expires_in).toBe(RULE_MAX_LIFETIME);
    });

    it("caps the token's lifetime at the ticket's remaining validity", async () => {
      const exchanged = await exchangeTicket({
        ticket: { lifetimeSeconds: 45 },
      });
      expect(exchanged.body.expires_in).toBe(45);
    });

    it("caps the token's lifetime at the endpoint's own, when it is the smallest", async () => {
      // The third ceiling. The policy's access token lifetime is an hour, so a
      // rule and a ticket that both permit longer do not extend it.
      await configureIssuer({ maxTokenLifetimeSecs: 86_400 });
      const exchanged = await exchangeTicket({
        ticket: { lifetimeSeconds: 86_400 },
      });
      expect(exchanged.body.expires_in).toBe(3600);
    });

    it("refuses a ticket whose signature does not verify", async () => {
      const refused = await exchangeTicket({
        subjectToken: tamperJws(await mintTicket()),
      });
      expect(refused.status).toBe(400);
      expect(refused.body.error).toBe("invalid_grant");
      expect(refused.body.error_description).toContain("signature");
    });

    it("refuses an expired ticket", async () => {
      const refused = await exchangeTicket({
        ticket: { lifetimeSeconds: -60 },
      });
      expect(refused.body.error).toBe("invalid_grant");
      expect(refused.body.error_description).toContain("expired");
    });

    it("refuses a ticket type this endpoint does not accept", async () => {
      const refused = await exchangeTicket({
        ticket: { claims: { ticket_type: "care-team-access" } },
      });
      expect(refused.body.error).toBe("invalid_grant");
      expect(refused.body.error_description).toContain("care-team-access");
    });

    it("refuses a ticket from an issuer that is not this endpoint's", async () => {
      // Signed with the configured issuer's own key, so the only thing wrong
      // with it is the issuer it names.
      const refused = await exchangeTicket({
        ticket: { issuer: "https://elsewhere.example.org" },
      });
      expect(refused.body.error).toBe("invalid_grant");
    });

    it("refuses rather than exchanging when the issuer's keys cannot be fetched", async () => {
      const cold = await createTestStack({
        allowPrivateOutboundFetches: true,
        endpoint: { fhirBaseUrl: `${fhir.origin}/fhir` },
      });
      try {
        await withTenantScope(cold.context.db, cold.scope, (bound) =>
          upsertEndpointTicketIssuer(bound, {
            issuer: issuer.issuer,
            jwksUri: issuer.jwksUri,
            acceptedTicketTypes: ["patient-self-access"],
            maxTokenLifetimeSecs: RULE_MAX_LIFETIME,
          }),
        );

        issuer.failJwksWith(503);
        const response = await postForm(
          cold,
          "/token",
          {
            grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
            subject_token: await issuer.mintTicket({
              issuedAt: cold.context.clock(),
            }),
            subject_token_type: JWT_SUBJECT_TOKEN_TYPE,
            scope: "patient/Patient.rs",
          },
          { authorization: basicAuth(cold.symmetricClient.clientId) },
        );
        expect(response.status).toBe(400);
        expect(((await response.json()) as ExchangeResponse).error).toBe(
          "invalid_grant",
        );
      } finally {
        issuer.failJwksWith(undefined);
        await cold.close();
      }
    });

    it("refuses a request carrying no subject token", async () => {
      const refused = await exchange({
        subject_token_type: JWT_SUBJECT_TOKEN_TYPE,
        scope: "patient/Patient.rs",
      });
      expect(refused.body.error).toBe("invalid_request");
    });

    it("refuses a subject token that is not presented as a JWT", async () => {
      const refused = await exchangeTicket({
        subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
      });
      expect(refused.body.error).toBe("invalid_request");
    });

    it("refuses a public client, which cannot authenticate", async () => {
      // A ticket is a bearer credential naming a patient. It is presented only
      // by a client whose identity the endpoint can verify. This one is
      // registered, active and known - and authenticates with nothing.
      const refused = await exchange(
        {
          subject_token: await mintTicket(),
          subject_token_type: JWT_SUBJECT_TOKEN_TYPE,
          scope: "patient/Patient.rs",
          client_id: stack.publicClient.clientId,
        },
        {},
      );
      expect(refused.body.error).toBe("invalid_client");
      expect(refused.status).toBe(401);
      expect(refused.body.access_token).toBeUndefined();
    });

    it("refuses a confidential client presenting no credential", async () => {
      const refused = await exchange(
        {
          subject_token: await mintTicket(),
          subject_token_type: JWT_SUBJECT_TOKEN_TYPE,
          scope: "patient/Patient.rs",
          client_id: stack.symmetricClient.clientId,
        },
        {},
      );
      expect(refused.body.error).toBe("invalid_client");
    });

    it("refuses a client presenting the wrong secret", async () => {
      const refused = await exchangeTicket({
        credential: {
          authorization: basicAuth(
            stack.symmetricClient.clientId,
            "not-the-secret",
          ),
        },
      });
      expect(refused.body.error).toBe("invalid_client");
    });

    it("refuses when the ticket's subject matches no patient", async () => {
      const refused = await exchangeTicket({
        ticket: {
          claims: {
            subject: { system: IHI_SYSTEM, value: "8003608500999999" },
          },
        },
      });
      expect(refused.body.error).toBe("invalid_grant");
      expect(refused.body.error_description).toContain("unknown");
    });

    it("refuses when the ticket's subject matches more than one patient", async () => {
      matchCount = 2;
      const refused = await exchangeTicket();
      expect(refused.body.error).toBe("invalid_grant");
      expect(refused.body.error_description).toContain("ambiguous");
    });

    it("never guesses across identifier systems", async () => {
      // A ticket minted in a system the endpoint's patients are not identified
      // in produces no match, not a match on the value alone.
      const refused = await exchangeTicket({
        ticket: {
          claims: {
            subject: { system: "http://example.org/other", value: IHI_VALUE },
          },
        },
      });
      expect(refused.body.error).toBe("invalid_grant");
      expect(refused.body.error_description).toContain("unknown");
    });

    it("fails the exchange with the cause when the FHIR server refuses", async () => {
      searchStatus = 503;
      const refused = await exchangeTicket();

      expect(refused.body.error).toBe("invalid_grant");
      expect(refused.body.error_description).toContain("503");
      expect(refused.body.access_token).toBeUndefined();
    });

    it("refuses an empty intersection rather than minting a scopeless token", async () => {
      const refused = await exchangeTicket({
        scope: "patient/Observation.rs",
        ticket: { claims: { smart_scopes: ["patient/Patient.rs"] } },
      });
      expect(refused.status).toBe(400);
      expect(refused.body.error).toBe("invalid_scope");
      expect(refused.body.access_token).toBeUndefined();
    });

    it("refuses when the policy grants none of what the ticket permits", async () => {
      // The third side of the intersection. The baseline policy restricts
      // `system/` scopes to backend services, so a ticket permitting one grants
      // nothing here however clearly it permitted it.
      const refused = await exchangeTicket({
        scope: "system/Patient.rs",
        ticket: { claims: { smart_scopes: ["system/Patient.rs"] } },
      });
      expect(refused.body.error).toBe("invalid_scope");
    });

    it("records every attempt, with the ticket identifier and never the ticket", async () => {
      const ticket = await mintTicket();
      const claims = decodePayload(ticket);
      await exchangeTicket({
        subjectToken: ticket,
        scope: "patient/Patient.rs",
      });
      await exchangeTicket({ ticket: { lifetimeSeconds: -60 } });

      const events = await auditEvents("token.ticket-exchanged");
      const serialised = JSON.stringify(events);
      const outcomes = events.map((event) => event.detail["outcome"]);

      expect(outcomes).toContain("exchanged");
      expect(outcomes).toContain("refused");
      expect(serialised).toContain(String(claims["jti"]));
      // The ticket is a bearer credential. Its identifier is what an operator
      // reviews by; the ticket itself must never be in the trail.
      expect(serialised).not.toContain(ticket);
      expect(serialised).not.toContain("eyJ");
    });

    it("records the ticket identifier when the ticket verifies but does not validate", async () => {
      // FR-016 asks for every attempt to be audited *by ticket identifier*, and
      // a refusal is the case an operator reviews the trail for. Once the
      // signature has verified, the `jti` is as trustworthy as it is on the
      // success path, so a refusal that reads the expiry has no excuse to
      // record the attempt anonymously.
      const expired = await mintTicket({ lifetimeSeconds: -60 });
      const claims = decodePayload(expired);
      await exchangeTicket({ subjectToken: expired });

      const [event] = await auditEvents("token.ticket-exchanged");
      expect(event?.detail["outcome"]).toBe("refused");
      expect(event?.detail["ticketId"]).toBe(String(claims["jti"]));
    });

    it("returns to refusing the grant type once the rule is removed", async () => {
      expect(await removeIssuer()).toBe(true);
      const refused = await exchangeTicket();
      expect(refused.body.error).toBe("unsupported_grant_type");
    });
  });

  describe("with an unreachable FHIR server", () => {
    it("fails the exchange rather than minting a token", async () => {
      // A socket that was bound and then closed, so the address is real and
      // nothing answers on it.
      const closed = await startLocalListener(
        async () => await Promise.resolve(jsonResponse({})),
      );
      const origin = closed.origin;
      await closed.close();

      const unreachable = await createTestStack({
        allowPrivateOutboundFetches: true,
        endpoint: { fhirBaseUrl: `${origin}/fhir` },
      });
      try {
        await withTenantScope(
          unreachable.context.db,
          unreachable.scope,
          (bound) =>
            upsertEndpointTicketIssuer(bound, {
              issuer: issuer.issuer,
              jwksUri: issuer.jwksUri,
              acceptedTicketTypes: ["patient-self-access"],
              maxTokenLifetimeSecs: RULE_MAX_LIFETIME,
            }),
        );

        const response = await postForm(
          unreachable,
          "/token",
          {
            grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
            subject_token: await issuer.mintTicket({
              issuedAt: unreachable.context.clock(),
            }),
            subject_token_type: JWT_SUBJECT_TOKEN_TYPE,
            scope: "patient/Patient.rs",
          },
          { authorization: basicAuth(unreachable.symmetricClient.clientId) },
        );
        const body = (await response.json()) as ExchangeResponse;
        expect(body.error).toBe("invalid_grant");
        expect(body.error_description ?? "").toContain("could not");
        expect(body.access_token).toBeUndefined();
      } finally {
        await unreachable.close();
      }
    });
  });
});

describeWithDatabase("ticket exchange rate limiting", () => {
  let stack: TestStack;
  let issuer: TrustAnchor;

  beforeAll(async () => {
    issuer = await startTrustAnchor();
    stack = await createTestStack({
      allowPrivateOutboundFetches: true,
      rateLimits: "enforced",
    });
    await withTenantScope(stack.context.db, stack.scope, (bound) =>
      upsertEndpointTicketIssuer(bound, {
        issuer: issuer.issuer,
        jwksUri: issuer.jwksUri,
        acceptedTicketTypes: ["patient-self-access"],
        maxTokenLifetimeSecs: RULE_MAX_LIFETIME,
      }),
    );
  });

  afterAll(async () => {
    await stack.close();
    await issuer.close();
  });

  it("throttles by client address and route", async () => {
    // The token endpoint's existing limiter, keyed by address and route only. A
    // key derived from the ticket would let a caller mint a fresh one per
    // attempt and never meet the limit.
    let limited = false;
    for (let attempt = 0; attempt < 200 && !limited; attempt += 1) {
      const response = await postForm(
        stack,
        "/token",
        {
          grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
          subject_token: "not.a.ticket",
          subject_token_type: JWT_SUBJECT_TOKEN_TYPE,
          scope: "patient/Patient.rs",
        },
        {
          authorization: basicAuth(
            stack.symmetricClient.clientId,
            TEST_CLIENT_SECRET,
          ),
        },
      );
      limited = response.status === 429;
    }
    expect(limited).toBe(true);
  });
});
