/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Vouched dynamic client registration, against a real database and a real anchor.
 *
 * The interesting assertions here are refusals, and a refusal is only evidence if
 * the fixture failed for the reason the test names - so every one of them is
 * arranged by `../test/trustAnchor.ts` rather than by hand-editing a token. An
 * expired statement carries a perfectly good signature; a tampered one still
 * decodes; a withdrawn key was published a moment before.
 *
 * The suite's spine is the pair of postures. An endpoint with no trust anchor rule
 * behaves exactly as Signet did before this feature existed - 404, nothing
 * advertised - and an endpoint with one accepts statements from that anchor and
 * nobody else. Removing the rule returns the first posture without revoking the
 * clients the second one created, which is a distinction the spec makes explicitly
 * and which nothing else would catch.
 *
 * The anchor binds loopback, so the stack is built with
 * `allowPrivateOutboundFetches`. One test builds a stack without it, which is what
 * proves the guard is in the path rather than the flag being a formality.
 *
 * Author: John Grimes
 */

import {
  deleteEndpointTrustAnchor,
  getClientByClientId,
  queryAuditEvents,
  upsertEndpointTrustAnchor,
  verifyPassword,
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

import { REMOTE_JWKS_MAX_AGE_SECONDS } from "./remoteJwks.js";
import { issuerPath, postJson } from "../test/flows.js";
import { createTestStack, testDatabaseUrl } from "../test/harness.js";
import { startTrustAnchor, tamperJws } from "../test/trustAnchor.js";

import type { TestStack } from "../test/harness.js";
import type { TrustAnchor } from "../test/trustAnchor.js";
import type { AuditAction } from "@signet/db";

const describeWithDatabase =
  testDatabaseUrl === undefined ? describe.skip : describe;

/** A registration response, as an app would read it. */
interface RegistrationResponse {
  readonly client_id?: string;
  readonly client_id_issued_at?: number;
  readonly client_secret?: string;
  readonly client_name?: string;
  readonly redirect_uris?: readonly string[];
  readonly grant_types?: readonly string[];
  readonly token_endpoint_auth_method?: string;
  readonly scope?: string;
  readonly error?: string;
  readonly error_description?: string;
}

describeWithDatabase("the registration endpoint", () => {
  let stack: TestStack;
  let anchor: TrustAnchor;

  beforeAll(async () => {
    anchor = await startTrustAnchor();
    stack = await createTestStack({
      // The anchor is on loopback. See the module header: one test below builds a
      // stack without this, so the flag is the thing being switched rather than
      // the guard being bypassed.
      allowPrivateOutboundFetches: true,
      endpoint: { supportsBackendServices: true },
    });
  });

  afterAll(async () => {
    await stack.close();
    await anchor.close();
  });

  /** Points the endpoint's trust anchor rule at the fixture anchor. */
  async function configureAnchor(maxVouchingDays = 30): Promise<void> {
    await withTenantScope(stack.context.db, stack.scope, (bound) =>
      upsertEndpointTrustAnchor(bound, {
        issuer: anchor.issuer,
        jwksUri: anchor.jwksUri,
        maxVouchingDays,
      }),
    );
  }

  /** Removes the rule, returning the endpoint to refusing registration. */
  async function removeAnchor(): Promise<boolean> {
    return await withTenantScope(stack.context.db, stack.scope, (bound) =>
      deleteEndpointTrustAnchor(bound),
    );
  }

  /** Posts a registration request and returns the status and the body. */
  async function register(
    body: unknown,
  ): Promise<{ status: number; body: RegistrationResponse }> {
    const response = await postJson(stack, "/register", body);
    return {
      status: response.status,
      body: (await response.json()) as RegistrationResponse,
    };
  }

  /** Posts a statement the anchor minted, with the case's overrides. */
  async function registerStatement(
    options: Parameters<TrustAnchor["mintStatement"]>[0] = {},
  ) {
    return await register({
      software_statement: await anchor.mintStatement(options),
    });
  }

  /** The stored client behind a registration response, read through the scope. */
  async function storedClient(clientId: string) {
    return await withTenantScope(stack.context.db, stack.scope, (bound) =>
      getClientByClientId(bound, clientId),
    );
  }

  /** The endpoint's audit events for one action, most recent first. */
  async function auditEvents(action: AuditAction) {
    const page = await withTenantScope(
      stack.context.db,
      stack.tenantScope,
      (bound) => queryAuditEvents(bound, { actions: [action], limit: 50 }),
    );
    return page.events;
  }

  beforeEach(async () => {
    await configureAnchor();
  });

  describe("without a trust anchor rule", () => {
    it("answers 404, exactly as it did before this feature existed", async () => {
      await removeAnchor();

      const refused = await register({
        software_statement: await anchor.mintStatement(),
      });
      expect(refused.status).toBe(404);
      expect(refused.body.client_id).toBeUndefined();
    });

    it("advertises no registration endpoint", async () => {
      await removeAnchor();

      const document = (await (
        await stack.app.request(
          `${issuerPath(stack)}/.well-known/smart-configuration`,
        )
      ).json()) as Record<string, unknown>;
      expect(Object.keys(document)).not.toContain("registration_endpoint");
    });

    it("refuses new registrations without revoking the clients it vouched for", async () => {
      // Removal is a decision about future registrations. The clients an anchor
      // already vouched for carry their own expiry, and withdrawing the rule is
      // not a revocation of them.
      const registered = await registerStatement();
      expect(registered.status).toBe(201);
      const clientId = registered.body.client_id ?? "";

      expect(await removeAnchor()).toBe(true);

      const afterwards = await registerStatement();
      expect(afterwards.status).toBe(404);

      const survivor = await storedClient(clientId);
      expect(survivor?.status).toBe("active");
      expect(survivor?.vouchedByIssuer).toBe(anchor.issuer);
    });
  });

  describe("with a trust anchor rule", () => {
    it("advertises the registration endpoint in both documents", async () => {
      const smart = (await (
        await stack.app.request(
          `${issuerPath(stack)}/.well-known/smart-configuration`,
        )
      ).json()) as Record<string, unknown>;
      const openId = (await (
        await stack.app.request(
          `${issuerPath(stack)}/.well-known/openid-configuration`,
        )
      ).json()) as Record<string, unknown>;

      expect(smart["registration_endpoint"]).toBe(`${stack.issuer}/register`);
      expect(openId["registration_endpoint"]).toBe(`${stack.issuer}/register`);
    });

    it("registers a client from the statement's metadata exactly", async () => {
      const registered = await registerStatement();

      expect(registered.status).toBe(201);
      expect(registered.body.client_id).toBeDefined();
      expect(registered.body.client_id_issued_at).toBeGreaterThan(0);
      expect(registered.body.client_name).toBe("Vouched test app");
      expect(registered.body.redirect_uris).toEqual([
        "https://app.example.org/callback",
      ]);
      expect(registered.body.token_endpoint_auth_method).toBe("none");

      const stored = await storedClient(registered.body.client_id ?? "");
      expect(stored?.name).toBe("Vouched test app");
      expect(stored?.clientType).toBe("public");
      expect(stored?.redirectUris).toEqual([
        "https://app.example.org/callback",
      ]);
      expect([...(stored?.grantTypes ?? [])].toSorted()).toEqual([
        "authorization_code",
        "refresh_token",
      ]);
      expect([...(stored?.allowedScopes ?? [])].toSorted()).toEqual([
        "fhirUser",
        "launch/patient",
        "openid",
        "patient/*.rs",
      ]);
      // Active immediately: the anchor's signature is the approval, which is the
      // whole difference between this and the developer portal.
      expect(stored?.status).toBe("active");
      expect(stored?.vouchedByIssuer).toBe(anchor.issuer);
      expect(stored?.vouchingExpiresAt).not.toBeNull();
    });

    it("returns a confidential client's secret once, and stores only its hash", async () => {
      const registered = await registerStatement({
        claims: { token_endpoint_auth_method: "client_secret_basic" },
      });

      expect(registered.status).toBe(201);
      const secret = registered.body.client_secret ?? "";
      expect(secret.length).toBeGreaterThan(20);

      const stored = await storedClient(registered.body.client_id ?? "");
      expect(stored?.clientType).toBe("confidential-symmetric");
      expect(stored?.secretHash).not.toBe(secret);
      expect(await verifyPassword(secret, stored?.secretHash ?? "")).toBe(true);
    });

    it("returns no secret to a public client", async () => {
      const registered = await registerStatement();
      expect(registered.body.client_secret).toBeUndefined();
    });

    it("refuses metadata asserted beside the statement rather than merging it", async () => {
      const refused = await register({
        software_statement: await anchor.mintStatement(),
        redirect_uris: ["https://attacker.example.org/cb"],
      });

      expect(refused.status).toBe(400);
      expect(refused.body.error).toBe("invalid_request");
    });

    it("refuses a request carrying no statement at all", async () => {
      const refused = await register({});
      expect(refused.status).toBe(400);
      expect(refused.body.error).toBe("invalid_request");
    });

    it("refuses a statement whose signature does not verify", async () => {
      const refused = await register({
        software_statement: tamperJws(await anchor.mintStatement()),
      });

      expect(refused.status).toBe(400);
      expect(refused.body.error).toBe("invalid_software_statement");
    });

    it("refuses an expired statement", async () => {
      const refused = await registerStatement({ lifetimeSeconds: -60 });
      expect(refused.status).toBe(400);
      expect(refused.body.error).toBe("invalid_software_statement");
      expect(refused.body.error_description).toContain("expired");
    });

    it("refuses a statement from an issuer that is not this endpoint's anchor", async () => {
      // Signed with the anchor's own key, so the only thing wrong with it is the
      // issuer it names. A test that also changed the key would pass against an
      // implementation that never looked at `iss`.
      const refused = await registerStatement({
        issuer: "https://elsewhere.example.org",
      });

      expect(refused.status).toBe(400);
      expect(refused.body.error).toBe("invalid_software_statement");
    });

    it("refuses a statement vouching for longer than the endpoint permits", async () => {
      await configureAnchor(1);
      const refused = await registerStatement({
        lifetimeSeconds: 5 * 86_400,
      });

      expect(refused.status).toBe(400);
      expect(refused.body.error).toBe("invalid_software_statement");
      expect(refused.body.error_description).toContain("days");
    });

    it("refuses a statement whose metadata Signet would not register", async () => {
      // The anchor vouches for the metadata's origin, not for its validity: a
      // relative redirect URI could never match at `/authorize`.
      const refused = await registerStatement({
        claims: { redirect_uris: ["/callback"] },
      });

      expect(refused.status).toBe(400);
      expect(refused.body.error).toBe("invalid_client_metadata");
    });

    it("refuses a client type the endpoint does not admit", async () => {
      const closed = await createTestStack({
        allowPrivateOutboundFetches: true,
        endpoint: { allowsPublicClients: false },
      });
      try {
        await withTenantScope(closed.context.db, closed.scope, (bound) =>
          upsertEndpointTrustAnchor(bound, {
            issuer: anchor.issuer,
            jwksUri: anchor.jwksUri,
            maxVouchingDays: 30,
          }),
        );

        const response = await postJson(closed, "/register", {
          software_statement: await anchor.mintStatement(),
        });
        expect(response.status).toBe(400);
        expect(((await response.json()) as RegistrationResponse).error).toBe(
          "invalid_client_metadata",
        );
      } finally {
        await closed.close();
      }
    });

    it("refuses a statement whose signing key the anchor no longer publishes", async () => {
      // Rotation, both halves. A statement signed by a superseded key that is
      // still in the published set verifies; the same key withdrawn does not.
      //
      // The withdrawal is observed on the far side of the key cache's window,
      // and that is the behaviour rather than a workaround for it: a cached
      // document may be reused for at most `REMOTE_JWKS_MAX_AGE_SECONDS`, so a
      // withdrawn key stops verifying within a window an operator can state.
      const started = stack.context.clock();
      const original = anchor.keyId;
      await anchor.addKey();

      const superseded = await registerStatement({ kid: original });
      expect(superseded.status).toBe(201);

      anchor.withdrawKey(original);
      const lapsed = new Date(
        started.getTime() + (REMOTE_JWKS_MAX_AGE_SECONDS + 60) * 1000,
      );
      stack.setNow(lapsed);
      try {
        const withdrawn = await registerStatement({
          kid: original,
          issuedAt: lapsed,
        });
        expect(withdrawn.status).toBe(400);
        expect(withdrawn.body.error).toBe("invalid_software_statement");
      } finally {
        stack.setNow(started);
      }
    });

    it("refuses rather than registering when the anchor's keys cannot be fetched", async () => {
      // On a stack whose key cache has never fetched, so the registration
      // genuinely depends on reaching the anchor. An unreachable anchor has not
      // vouched for anything, and treating its silence as assent is the one
      // mistake this route exists to avoid.
      const cold = await createTestStack({ allowPrivateOutboundFetches: true });
      try {
        await withTenantScope(cold.context.db, cold.scope, (bound) =>
          upsertEndpointTrustAnchor(bound, {
            issuer: anchor.issuer,
            jwksUri: anchor.jwksUri,
            maxVouchingDays: 30,
          }),
        );

        anchor.failJwksWith(503);
        const refused = await postJson(cold, "/register", {
          software_statement: await anchor.mintStatement(),
        });
        expect(refused.status).toBe(400);
        expect(((await refused.json()) as RegistrationResponse).error).toBe(
          "invalid_software_statement",
        );

        // The same request once the anchor answers again, so the refusal above
        // is the outage rather than anything else about this stack.
        anchor.failJwksWith(undefined);
        const accepted = await postJson(cold, "/register", {
          software_statement: await anchor.mintStatement(),
        });
        expect(accepted.status).toBe(201);
      } finally {
        anchor.failJwksWith(undefined);
        await cold.close();
      }
    });

    it("honours a statement once, refusing the second presentation", async () => {
      const statement = await anchor.mintStatement();

      const first = await register({ software_statement: statement });
      expect(first.status).toBe(201);

      const second = await register({ software_statement: statement });
      expect(second.status).toBe(400);
      expect(second.body.error).toBe("invalid_software_statement");
      expect(second.body.error_description).toContain("already");
    });

    it("creates exactly one client when two registrations race on one statement", async () => {
      // The unique constraint on (endpoint_id, vouched_statement_id) is what
      // arbitrates. A read-then-insert would let both attempts find nothing.
      const statement = await anchor.mintStatement();

      const [a, b] = await Promise.all([
        register({ software_statement: statement }),
        register({ software_statement: statement }),
      ]);

      const outcomes = [a.status, b.status].toSorted();
      expect(outcomes).toEqual([201, 400]);
      const created = [a, b].filter((result) => result.status === 201);
      expect(created).toHaveLength(1);
    });

    it("records every attempt in the audit trail, with no statement or secret in it", async () => {
      const registered = await registerStatement({
        claims: { token_endpoint_auth_method: "client_secret_basic" },
      });
      const secret = registered.body.client_secret ?? "";
      await registerStatement({ lifetimeSeconds: -60 });

      const events = await auditEvents("client.registration-attempted");
      const serialised = JSON.stringify(events);

      const outcomes = events.map((event) => event.detail["outcome"]);
      expect(outcomes).toContain("registered");
      expect(outcomes).toContain("refused");
      // The anchor and the statement identifier are what an operator reviews by;
      // the statement itself and the secret are what must never be there.
      expect(serialised).toContain(anchor.issuer);
      expect(serialised).not.toContain(secret);
      expect(serialised).not.toContain("eyJ");
    });
  });

  describe("without permission to reach the anchor", () => {
    it("refuses a fetch the outbound guard would block", async () => {
      // The same anchor, the same statement, a stack that has not been told to
      // permit loopback. A registration endpoint calling `fetch` directly would
      // register the client here.
      const guarded = await createTestStack();
      try {
        await withTenantScope(guarded.context.db, guarded.scope, (bound) =>
          upsertEndpointTrustAnchor(bound, {
            issuer: anchor.issuer,
            jwksUri: anchor.jwksUri,
            maxVouchingDays: 30,
          }),
        );

        const response = await postJson(guarded, "/register", {
          software_statement: await anchor.mintStatement(),
        });
        expect(response.status).toBe(400);
        expect(((await response.json()) as RegistrationResponse).error).toBe(
          "invalid_software_statement",
        );
      } finally {
        await guarded.close();
      }
    });
  });
});

describeWithDatabase("registration rate limiting", () => {
  let stack: TestStack;
  let anchor: TrustAnchor;

  beforeAll(async () => {
    anchor = await startTrustAnchor();
    stack = await createTestStack({
      allowPrivateOutboundFetches: true,
      rateLimits: "enforced",
    });
    await withTenantScope(stack.context.db, stack.scope, (bound) =>
      upsertEndpointTrustAnchor(bound, {
        issuer: anchor.issuer,
        jwksUri: anchor.jwksUri,
        maxVouchingDays: 30,
      }),
    );
  });

  afterAll(async () => {
    await stack.close();
    await anchor.close();
  });

  it("throttles by client address and route", async () => {
    // Keyed by address and route only. A key derived from the statement would let
    // a caller mint a fresh one per attempt and never meet the limit.
    let limited = false;
    for (let attempt = 0; attempt < 80 && !limited; attempt += 1) {
      const response = await postJson(stack, "/register", {
        software_statement: "not.a.statement",
      });
      limited = response.status === 429;
    }
    expect(limited).toBe(true);
  });
});
