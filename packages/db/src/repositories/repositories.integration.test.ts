/**
 * Repository behaviour that only Postgres can confirm.
 *
 * The unit tests cover every pure judgement - what counts as expired, what counts
 * as reuse. What they cannot cover is the part that makes those judgements safe:
 * that the claim on a single-use row is atomic, that two concurrent redemptions
 * produce one winner, that reuse detection revokes a family, and that a tenant
 * predicate actually excludes another tenant's rows. Those are properties of SQL
 * statements under concurrency, so they are asserted against a real server.
 *
 * Skipped unless `SIGNET_TEST_DATABASE_URL` names a throwaway database. CI has none
 * yet, and a suite that connected regardless would fail the build.
 *
 * Every test creates its own tenants and deletes them afterwards rather than
 * truncating: Vitest runs files in parallel, and a suite that emptied shared tables
 * would break whichever file happened to be running beside it.
 *
 * Author: John Grimes
 */

import { eq, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import { fileURLToPath } from "node:url";
import postgres from "postgres";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { TENANT_SETTING, withTenantScope } from "../rls.js";
import {
  introspectAccessToken,
  recordAccessToken,
  revokeAccessToken,
} from "./accessTokens.js";
import { createAdminUser } from "./adminUsers.js";
import {
  consumeAuthorizationCode,
  createAuthorizationCode,
  findAuthorizationCode,
} from "./authorizationCodes.js";
import { createAuthorizationSession } from "./authorizationSessions.js";
import { approveClientRequest, createClientRequest } from "./clientRequests.js";
import { createClient, getClientByClientId } from "./clients.js";
import { listLiveConsents, recordConsent, revokeConsent } from "./consents.js";
import {
  getActiveEndpointKey,
  insertEndpointKey,
  promoteNextEndpointKey,
} from "./endpointKeys.js";
import { createEndpoint, getEndpoint, listEndpoints } from "./endpoints.js";
import { createEndUser, listSelectablePersonas } from "./endUsers.js";
import { hasSeenJti, recordJti } from "./jtiReplay.js";
import {
  consumeLaunchContext,
  createLaunchContext,
  findLaunchContext,
} from "./launchContexts.js";
import { removeTenantMember, setTenantMemberRole } from "./members.js";
import {
  createPolicyVersion,
  getEffectivePolicy,
  getPublishedPolicy,
  listPolicyVersions,
  publishPolicy,
  setClientPolicyOverride,
} from "./policies.js";
import {
  findRefreshToken,
  issueRefreshToken,
  redeemAndRotateRefreshToken,
  redeemRefreshToken,
  rotateRefreshToken,
} from "./refreshTokens.js";
import {
  clientScopeFromRow,
  endpointScopeFromRow,
  resolveClientScope,
  resolveIssuer,
  tenantScopeFromRow,
  TenantScopeViolationError,
} from "./scope.js";
import { sweepExpiredRuntimeRows } from "./sweep.js";
import { createTenant } from "./tenants.js";
import { clients } from "../schema/clients.js";
import { endpoints } from "../schema/endpoints.js";
import { launchContexts, refreshTokens } from "../schema/runtime.js";
import { tenants } from "../schema/tenancy.js";
import {
  prepareRowLevelSecurityFixtures,
  RLS_TEST_ROLE,
} from "../test/rlsRole.js";
import { isTestSchemaReady } from "../test/schemaReady.js";

import type { Executor } from "./executor.js";
import type {
  BoundTenantScope,
  ClientScope,
  EndpointScope,
  TenantScope,
} from "./scope.js";
import type { PolicyDocument } from "@signet/core";

const databaseUrl = process.env.SIGNET_TEST_DATABASE_URL;

const describeWithDatabase =
  databaseUrl === undefined ? describe.skip : describe;

const migrationsFolder = fileURLToPath(
  new URL("../../drizzle", import.meta.url),
);

/** The same lock the audit suite takes; see its commentary. */
const MIGRATION_LOCK_KEY = 5_348_464;

/** A minimal but valid policy document. */
const POLICY: PolicyDocument = {
  version: 1,
  scopeGrants: [{ match: "patient/*.rs", allow: true }],
  claimRules: [],
  contextRules: [],
  defaults: { accessTokenTtl: 300, refreshTokenTtl: 2_592_000 },
};

/** Everything a test needs to exercise one endpoint's runtime tables. */
interface Fixture {
  readonly tenantScope: TenantScope;
  readonly endpointScope: EndpointScope;
  readonly clientScope: ClientScope;
}

/** Resolves after `milliseconds`, used to overlap two transactions. */
function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

/**
 * Narrows a repository result to its success branch, or fails the test.
 *
 * Asserting inside `if (result.ok)` would silently pass when the call failed -
 * the block simply would not run. Throwing here fails loudly and narrows the
 * type, so the assertions that follow can read the success fields directly.
 */
function expectOk<T extends { readonly ok: boolean }>(
  result: T,
): Extract<T, { readonly ok: true }> {
  if (!result.ok) {
    throw new Error(`expected success, got ${JSON.stringify(result)}`);
  }
  return result as Extract<T, { readonly ok: true }>;
}

/** Issues a live refresh token on a fixture's client. */
async function issueRefresh(
  db: Executor,
  fixture: Fixture,
  tokenHash: string,
  expiresAt = new Date(Date.now() + 600_000),
) {
  return await issueRefreshToken(db, fixture.clientScope, {
    tokenHash,
    subject: "user-1",
    scope: "patient/Observation.rs",
    expiresAt,
  });
}

/** Creates a console identity, which belongs to no tenant. */
async function newAdmin(db: Executor, email: string): Promise<string> {
  const user = await createAdminUser(db, {
    email,
    passwordHash: "$argon2id$placeholder",
    displayName: "Admin",
  });
  return user.id;
}

describeWithDatabase("tenant-scoped repositories against Postgres", () => {
  let sql_: ReturnType<typeof postgres> | undefined;
  let connection: ReturnType<typeof drizzle>;
  let db: Executor;
  const createdTenantIds: string[] = [];
  let sequence = 0;

  beforeAll(async () => {
    sql_ = postgres(databaseUrl ?? "", { max: 5, onnotice: () => {} });
    connection = drizzle(sql_);

    // See the audit suite: the schema is normally already there, migrated once by
    // the Vitest global setup before any worker started.
    if (!isTestSchemaReady()) {
      await sql_`select pg_advisory_lock(${MIGRATION_LOCK_KEY})`;
      try {
        await migrate(connection, { migrationsFolder });
      } finally {
        await sql_`select pg_advisory_unlock(${MIGRATION_LOCK_KEY})`;
      }
    }

    // `drizzle(sql)` and `Executor` differ in a phantom schema type parameter
    // only; the query surface used here is identical.
    db = connection as unknown as Executor;
  }, 60_000);

  afterEach(async () => {
    // Cascades through every tenant-owned table, so each test starts clean without
    // truncating anything a parallel suite might be using.
    while (createdTenantIds.length > 0) {
      const id = createdTenantIds.pop();
      if (id !== undefined) {
        await connection.delete(tenants).where(eq(tenants.id, id));
      }
    }
  });

  afterAll(async () => {
    await sql_?.end();
  });

  /**
   * Runs a repository call in a transaction declared for its scope.
   *
   * Every function that touches tenant-owned data now takes a bound scope, and the
   * fixtures hold unbound ones - a binding cannot outlive the transaction that made
   * it, so it cannot be created once in `beforeAll` and reused. Binding per call is
   * also what the server does, so the atomicity boundaries these tests assert on are
   * the ones production has.
   */
  function inScope<S extends TenantScope, T>(
    scope: S,
    work: (bound: S & BoundTenantScope) => Promise<T>,
  ): Promise<T> {
    return withTenantScope(db, scope, work);
  }

  /** A distinct suffix, so slugs and identifiers never collide across tests. */
  function unique(): string {
    sequence += 1;
    return `${Date.now().toString(36)}-${sequence}`;
  }

  /** Creates a tenant, registered for deletion after the test. */
  async function newTenant(): Promise<TenantScope> {
    const tenant = await createTenant(db, {
      slug: `repo-${unique()}`,
      name: "Repository test tenant",
    });
    createdTenantIds.push(tenant.id);
    return tenantScopeFromRow(tenant);
  }

  /** Creates a tenant, an endpoint and a client, and scopes for each. */
  async function newFixture(
    options: { readonly isProduction?: boolean } = {},
  ): Promise<Fixture> {
    const tenantScope = await newTenant();
    const endpoint = await withTenantScope(db, tenantScope, (bound) =>
      createEndpoint(bound, {
        slug: `e-${unique()}`,
        name: "Endpoint",
        fhirBaseUrl: "https://fhir.example.org/fhir",
        isProduction: options.isProduction ?? true,
      }),
    );
    const endpointScope = endpointScopeFromRow(tenantScope, endpoint);

    const client = await withTenantScope(db, endpointScope, (bound) =>
      createClient(bound, {
        clientId: `client-${unique()}`,
        name: "Test app",
        clientType: "public",
        grantTypes: ["authorization_code", "refresh_token"],
      }),
    );

    return {
      tenantScope,
      endpointScope,
      clientScope: clientScopeFromRow(endpointScope, client),
    };
  }

  /**
   * Runs one claim while another is still holding the row.
   *
   * `Promise.all` over two claims proves very little: whether the two statements
   * actually overlap is up to the scheduler, and if the first commits before the
   * second begins then a read-then-write implementation passes the test. So the
   * first claim is made inside a transaction that is deliberately held open - its
   * row lock with it - the second is started against a different connection, and
   * only then is the first allowed to commit.
   *
   * The second claim therefore blocks on the lock and re-evaluates its predicate
   * against the row the first committed, which is the exact behaviour the
   * conditional `UPDATE` relies on. A read-then-write would have read the row
   * before that commit and overwritten it afterwards, and both callers would win.
   *
   * @param claim - The repository call under test, run twice.
   * @returns The holder's result first, then the contender's.
   */
  async function raceOnOneRow<T>(
    claim: (executor: Executor) => Promise<T>,
  ): Promise<readonly [T, T]> {
    const holder = db.transaction(async (tx) => {
      const result = await claim(tx);
      // The transaction - and the row lock the claim took - stays open well past
      // the moment the contender below reaches the same row.
      await delay(600);
      return result;
    });

    // Long enough for the holder's statement to have taken its lock, and early
    // enough that the contender is certainly blocked when the holder commits.
    await delay(200);
    const contender = claim(db);

    return [await holder, await contender];
  }

  /** An authorization session on the fixture's client. */
  async function newSession(fixture: Fixture) {
    return await createAuthorizationSession(db, fixture.clientScope, {
      redirectUri: "https://app.example.org/callback",
      expiresAt: new Date(Date.now() + 600_000),
      requestedScopes: ["patient/Observation.rs"],
    });
  }

  describe("tenant isolation", () => {
    it("lists only the scope's own endpoints", async () => {
      const mine = await newFixture();
      const theirs = await newFixture();

      const listed = await withTenantScope(db, mine.tenantScope, (bound) =>
        listEndpoints(bound),
      );
      expect(listed).toHaveLength(1);
      expect(listed[0]?.id).toBe(mine.endpointScope.endpointId);

      const foreign = await withTenantScope(db, mine.tenantScope, (bound) =>
        getEndpoint(bound, theirs.endpointScope.endpointId),
      );
      expect(foreign).toBeUndefined();
    });

    it("resolves an issuer from its two path segments", async () => {
      const fixture = await newFixture();
      const resolved = await resolveIssuer(
        db,
        fixture.tenantScope.tenantSlug,
        fixture.endpointScope.endpointSlug,
      );

      expect(resolved?.scope.endpointId).toBe(fixture.endpointScope.endpointId);
      expect(resolved?.endpoint.fhirBaseUrl).toBe(
        "https://fhir.example.org/fhir",
      );
      expect(
        await resolveIssuer(db, fixture.tenantScope.tenantSlug, "no-such"),
      ).toBeUndefined();
    });

    it("will not resolve a client registered on another endpoint", async () => {
      const mine = await newFixture();
      const theirs = await newFixture();

      // client_id is globally unique, so this is the lookup that would leak
      // across tenants without an endpoint predicate.
      const resolved = await withTenantScope(db, mine.endpointScope, (bound) =>
        resolveClientScope(bound, theirs.clientScope.clientId),
      );
      expect(resolved).toBeUndefined();

      expect(
        await withTenantScope(db, mine.endpointScope, (bound) =>
          getClientByClientId(bound, theirs.clientScope.clientId),
        ),
      ).toBeUndefined();
    });
  });

  describe("authorization codes", () => {
    it("redeems a code once and returns its session", async () => {
      const fixture = await newFixture();
      const session = await newSession(fixture);
      await createAuthorizationCode(db, fixture.endpointScope, session, {
        codeHash: "code-hash-1",
        expiresAt: new Date(Date.now() + 60_000),
      });

      const first = await consumeAuthorizationCode(
        db,
        fixture.endpointScope,
        "code-hash-1",
      );
      const claimed = expectOk(first);
      expect(claimed.session.id).toBe(session.id);
      expect(claimed.code.consumedAt).not.toBeNull();

      const second = await consumeAuthorizationCode(
        db,
        fixture.endpointScope,
        "code-hash-1",
      );
      expect(second).toEqual({ ok: false, reason: "already-consumed" });
    });

    it("lets exactly one of two overlapping redemptions win", async () => {
      const fixture = await newFixture();
      const session = await newSession(fixture);
      await createAuthorizationCode(db, fixture.endpointScope, session, {
        codeHash: "code-hash-race",
        expiresAt: new Date(Date.now() + 60_000),
      });

      const [first, second] = await raceOnOneRow((executor) =>
        consumeAuthorizationCode(
          executor,
          fixture.endpointScope,
          "code-hash-race",
        ),
      );

      expect(first.ok).toBe(true);
      expect(second).toEqual({ ok: false, reason: "already-consumed" });
    });

    it("refuses an expired code without consuming it", async () => {
      const fixture = await newFixture();
      const session = await newSession(fixture);
      await createAuthorizationCode(db, fixture.endpointScope, session, {
        codeHash: "code-hash-old",
        expiresAt: new Date(Date.now() - 1000),
      });

      const result = await consumeAuthorizationCode(
        db,
        fixture.endpointScope,
        "code-hash-old",
      );
      expect(result).toEqual({ ok: false, reason: "expired" });
    });

    it("cannot redeem another endpoint's code, and leaves it unconsumed", async () => {
      const mine = await newFixture();
      const theirs = await newFixture();
      const session = await newSession(theirs);
      await createAuthorizationCode(db, theirs.endpointScope, session, {
        codeHash: "code-hash-foreign",
        expiresAt: new Date(Date.now() + 60_000),
      });

      const result = await consumeAuthorizationCode(
        db,
        mine.endpointScope,
        "code-hash-foreign",
      );
      expect(result).toEqual({ ok: false, reason: "not-found" });

      // The important half: the attempt must not have spent the victim's code.
      const untouched = await findAuthorizationCode(
        db,
        theirs.endpointScope,
        "code-hash-foreign",
      );
      expect(untouched?.consumedAt).toBeNull();
    });

    it("refuses a code minted against another endpoint's session", async () => {
      const mine = await newFixture();
      const theirs = await newFixture();
      const session = await newSession(theirs);

      await expect(
        createAuthorizationCode(db, mine.endpointScope, session, {
          codeHash: "code-hash-mismatch",
          expiresAt: new Date(Date.now() + 60_000),
        }),
      ).rejects.toThrow(TenantScopeViolationError);
    });
  });

  describe("launch handles", () => {
    it("redeems a bound handle once, for the client it was bound to", async () => {
      const fixture = await newFixture();
      await createLaunchContext(db, fixture.endpointScope, {
        handleHash: "launch-1",
        context: { patient: "Patient/1" },
        expiresAt: new Date(Date.now() + 60_000),
        boundTo: fixture.clientScope,
      });

      const first = await consumeLaunchContext(
        db,
        fixture.clientScope,
        "launch-1",
      );
      expect(expectOk(first).launch.context).toEqual({ patient: "Patient/1" });

      expect(
        await consumeLaunchContext(db, fixture.clientScope, "launch-1"),
      ).toEqual({ ok: false, reason: "already-consumed" });
    });

    it("refuses the wrong client and leaves the handle unconsumed", async () => {
      const fixture = await newFixture();
      const other = await withTenantScope(db, fixture.endpointScope, (bound) =>
        createClient(bound, {
          clientId: `client-${unique()}`,
          name: "Another app",
          clientType: "public",
          grantTypes: ["authorization_code"],
        }),
      );
      const otherScope = clientScopeFromRow(fixture.endpointScope, other);

      await createLaunchContext(db, fixture.endpointScope, {
        handleHash: "launch-bound",
        context: { patient: "Patient/2" },
        expiresAt: new Date(Date.now() + 60_000),
        boundTo: fixture.clientScope,
      });

      expect(
        await consumeLaunchContext(db, otherScope, "launch-bound"),
      ).toEqual({ ok: false, reason: "client-mismatch" });

      const untouched = await findLaunchContext(
        db,
        fixture.endpointScope,
        "launch-bound",
      );
      expect(untouched?.consumedAt).toBeNull();
    });

    it("lets any client redeem an unbound handle", async () => {
      const fixture = await newFixture();
      await createLaunchContext(db, fixture.endpointScope, {
        handleHash: "launch-open",
        context: {},
        expiresAt: new Date(Date.now() + 60_000),
      });

      const redemption = await consumeLaunchContext(
        db,
        fixture.clientScope,
        "launch-open",
      );
      expect(redemption.ok).toBe(true);
    });

    it("refuses to bind a handle to a client from another endpoint", async () => {
      const mine = await newFixture();
      const theirs = await newFixture();

      await expect(
        createLaunchContext(db, mine.endpointScope, {
          handleHash: "launch-foreign",
          context: {},
          expiresAt: new Date(Date.now() + 60_000),
          boundTo: theirs.clientScope,
        }),
      ).rejects.toThrow(TenantScopeViolationError);
    });
  });

  describe("refresh token rotation", () => {
    it("rotates into the same family and links the predecessor", async () => {
      const fixture = await newFixture();
      const original = await issueRefresh(db, fixture, "refresh-a");

      const rotation = await redeemAndRotateRefreshToken(
        db,
        fixture.clientScope,
        "refresh-a",
        {
          tokenHash: "refresh-b",
          scope: "patient/Observation.rs",
          expiresAt: new Date(Date.now() + 600_000),
        },
      );

      expect(rotation.ok).toBe(true);
      if (!rotation.ok) {
        return;
      }
      expect(rotation.replacement.familyId).toBe(original.familyId);
      expect(rotation.replacement.subject).toBe("user-1");

      const predecessor = await findRefreshToken(
        db,
        fixture.endpointScope,
        "refresh-a",
      );
      expect(predecessor?.revokedAt).not.toBeNull();
      expect(predecessor?.replacedById).toBe(rotation.replacement.id);
    });

    it("revokes the whole family when a rotated token is presented again", async () => {
      const fixture = await newFixture();
      await issueRefresh(db, fixture, "refresh-1");
      const rotation = await redeemAndRotateRefreshToken(
        db,
        fixture.clientScope,
        "refresh-1",
        {
          tokenHash: "refresh-2",
          scope: "patient/Observation.rs",
          expiresAt: new Date(Date.now() + 600_000),
        },
      );
      expect(rotation.ok).toBe(true);

      const reuse = await redeemRefreshToken(
        db,
        fixture.endpointScope,
        "refresh-1",
      );
      expect(reuse.ok).toBe(false);
      if (reuse.ok) {
        return;
      }
      expect(reuse.reason).toBe("reused");
      // The successor was live; detecting the theft must have killed it.
      expect(reuse.familyRevoked).toBe(1);

      const successor = await findRefreshToken(
        db,
        fixture.endpointScope,
        "refresh-2",
      );
      expect(successor?.revokedAt).not.toBeNull();

      // And the successor now reads as revoked rather than as reused: it has no
      // successor of its own, so it is not evidence of a second theft.
      const afterwards = await redeemRefreshToken(
        db,
        fixture.endpointScope,
        "refresh-2",
      );
      expect(afterwards).toEqual({
        ok: false,
        reason: "revoked",
        familyRevoked: 0,
      });
    });

    it("lets exactly one of two overlapping redemptions win", async () => {
      const fixture = await newFixture();
      await issueRefresh(db, fixture, "refresh-race");

      const [first, second] = await raceOnOneRow((executor) =>
        redeemRefreshToken(executor, fixture.endpointScope, "refresh-race"),
      );

      expect(first.ok).toBe(true);
      // The loser sees a revoked token with no successor, which must not be
      // mistaken for theft - that would revoke the family and log the legitimate
      // user out over a lost race.
      expect(second).toEqual({
        ok: false,
        reason: "revoked",
        familyRevoked: 0,
      });
    });

    it("refuses an expired token, and does not touch its family", async () => {
      const fixture = await newFixture();
      await issueRefreshToken(db, fixture.clientScope, {
        tokenHash: "refresh-old",
        subject: "user-1",
        scope: "patient/Observation.rs",
        expiresAt: new Date(Date.now() - 1000),
      });

      expect(
        await redeemRefreshToken(db, fixture.endpointScope, "refresh-old"),
      ).toEqual({ ok: false, reason: "expired", familyRevoked: 0 });
    });

    it("will not rotate another client's token into this client's family", async () => {
      const mine = await newFixture();
      const theirs = await newFixture();
      const foreign = await issueRefresh(db, theirs, "refresh-foreign");

      await expect(
        rotateRefreshToken(db, mine.clientScope, foreign, {
          tokenHash: "refresh-stolen",
          scope: "patient/Observation.rs",
          expiresAt: new Date(Date.now() + 600_000),
        }),
      ).rejects.toThrow(TenantScopeViolationError);
    });

    it("does not see another endpoint's token", async () => {
      const mine = await newFixture();
      const theirs = await newFixture();
      await issueRefresh(db, theirs, "refresh-elsewhere");

      expect(
        await redeemRefreshToken(db, mine.endpointScope, "refresh-elsewhere"),
      ).toEqual({ ok: false, reason: "not-found", familyRevoked: 0 });

      const untouched = await findRefreshToken(
        db,
        theirs.endpointScope,
        "refresh-elsewhere",
      );
      expect(untouched?.revokedAt).toBeNull();
    });
  });

  describe("the jti replay ledger", () => {
    it("accepts an assertion once and refuses it thereafter", async () => {
      const fixture = await newFixture();
      const expiresAt = new Date(Date.now() + 300_000);

      expect(
        await recordJti(db, fixture.clientScope, "jti-1", expiresAt),
      ).toEqual({ status: "recorded" });
      expect(
        await recordJti(db, fixture.clientScope, "jti-1", expiresAt),
      ).toEqual({ status: "already-seen" });
      expect(await hasSeenJti(db, fixture.clientScope, "jti-1")).toBe(true);
    });

    it("keeps a separate ledger per client", async () => {
      const fixture = await newFixture();
      const other = await withTenantScope(db, fixture.endpointScope, (bound) =>
        createClient(bound, {
          clientId: `client-${unique()}`,
          name: "Second app",
          clientType: "confidential-asymmetric",
          grantTypes: ["client_credentials"],
        }),
      );
      const otherScope = clientScopeFromRow(fixture.endpointScope, other);
      const expiresAt = new Date(Date.now() + 300_000);

      await recordJti(db, fixture.clientScope, "shared-jti", expiresAt);

      // jti values are only unique per issuer, so a second client may legitimately
      // choose the same one.
      expect(await recordJti(db, otherScope, "shared-jti", expiresAt)).toEqual({
        status: "recorded",
      });
    });

    it("leaves the transaction usable after a replay", async () => {
      const fixture = await newFixture();
      const expiresAt = new Date(Date.now() + 300_000);
      await recordJti(db, fixture.clientScope, "jti-tx", expiresAt);

      // A raised unique violation would abort the surrounding transaction and take
      // the rest of the token exchange with it.
      await db.transaction(async (tx) => {
        expect(
          await recordJti(tx, fixture.clientScope, "jti-tx", expiresAt),
        ).toEqual({ status: "already-seen" });
        const rows = await tx.select().from(clients).limit(1);
        expect(rows.length).toBeGreaterThan(0);
      });
    });
  });

  describe("policies", () => {
    it("allocates versions in sequence, including concurrently", async () => {
      const fixture = await newFixture();

      const first = await withTenantScope(db, fixture.endpointScope, (bound) =>
        createPolicyVersion(bound, {
          document: POLICY,
        }),
      );
      expect(expectOk(first).policy.version).toBe(1);

      const concurrent = await Promise.all([
        withTenantScope(db, fixture.endpointScope, (bound) =>
          createPolicyVersion(bound, { document: POLICY }),
        ),
        withTenantScope(db, fixture.endpointScope, (bound) =>
          createPolicyVersion(bound, { document: POLICY }),
        ),
      ]);
      expect(concurrent.map((result) => result.ok)).toEqual([true, true]);

      const allVersions = await withTenantScope(
        db,
        fixture.endpointScope,
        (bound) => listPolicyVersions(bound),
      );
      const versions = allVersions
        .map((policy) => policy.version)
        .toSorted((a, b) => a - b);
      expect(versions).toEqual([1, 2, 3]);
    });

    it("publishes exactly one version at a time", async () => {
      const fixture = await newFixture();
      await withTenantScope(db, fixture.endpointScope, (bound) =>
        createPolicyVersion(bound, {
          document: POLICY,
        }),
      );
      await withTenantScope(db, fixture.endpointScope, (bound) =>
        createPolicyVersion(bound, {
          document: POLICY,
        }),
      );

      const publishedFirst = await withTenantScope(
        db,
        fixture.endpointScope,
        (bound) => publishPolicy(bound, 1),
      );
      expect(publishedFirst.ok).toBe(true);
      const afterFirst = await withTenantScope(
        db,
        fixture.endpointScope,
        (bound) => getPublishedPolicy(bound),
      );
      expect(afterFirst?.version).toBe(1);

      const publishedSecond = await withTenantScope(
        db,
        fixture.endpointScope,
        (bound) => publishPolicy(bound, 2),
      );
      expect(publishedSecond.ok).toBe(true);
      const versions = await withTenantScope(
        db,
        fixture.endpointScope,
        (bound) => listPolicyVersions(bound),
      );
      expect(versions.filter((policy) => policy.published)).toHaveLength(1);
      const afterSecond = await withTenantScope(
        db,
        fixture.endpointScope,
        (bound) => getPublishedPolicy(bound),
      );
      expect(afterSecond?.version).toBe(2);
    });

    it("leaves the published version alone when the target does not exist", async () => {
      const fixture = await newFixture();
      await withTenantScope(db, fixture.endpointScope, (bound) =>
        createPolicyVersion(bound, {
          document: POLICY,
        }),
      );
      await withTenantScope(db, fixture.endpointScope, (bound) =>
        publishPolicy(bound, 1),
      );

      expect(
        await withTenantScope(db, fixture.endpointScope, (bound) =>
          publishPolicy(bound, 99),
        ),
      ).toEqual({
        ok: false,
        reason: "version-not-found",
      });

      // The endpoint must not have been left with nothing published.
      const stillPublished = await withTenantScope(
        db,
        fixture.endpointScope,
        (bound) => getPublishedPolicy(bound),
      );
      expect(stillPublished?.version).toBe(1);
    });

    it("prefers a client override over the endpoint's published policy", async () => {
      const fixture = await newFixture();
      expect(
        await withTenantScope(db, fixture.clientScope, (bound) =>
          getEffectivePolicy(bound),
        ),
      ).toBeUndefined();

      await withTenantScope(db, fixture.endpointScope, (bound) =>
        createPolicyVersion(bound, {
          document: POLICY,
        }),
      );
      await withTenantScope(db, fixture.endpointScope, (bound) =>
        publishPolicy(bound, 1),
      );

      const endpointPolicy = await withTenantScope(
        db,
        fixture.clientScope,
        (bound) => getEffectivePolicy(bound),
      );
      expect(endpointPolicy?.source).toBe("endpoint");
      expect(endpointPolicy?.version).toBe(1);

      const override: PolicyDocument = {
        ...POLICY,
        scopeGrants: [{ match: "system/*.rs", allow: true }],
      };
      await withTenantScope(db, fixture.clientScope, (bound) =>
        setClientPolicyOverride(bound, override),
      );

      const effective = await withTenantScope(
        db,
        fixture.clientScope,
        (bound) => getEffectivePolicy(bound),
      );
      expect(effective?.source).toBe("client-override");
      expect(effective?.document.scopeGrants[0]?.match).toBe("system/*.rs");
    });
  });

  describe("membership", () => {
    it("refuses to remove or demote the last owner", async () => {
      const scope = await newTenant();
      const owner = await newAdmin(db, `admin-${unique()}@example.org`);
      const invited = await inScope(scope, (bound) =>
        setTenantMemberRole(bound, owner, "owner"),
      );
      expect(invited.ok).toBe(true);

      expect(
        await inScope(scope, (bound) => removeTenantMember(bound, owner)),
      ).toEqual({
        ok: false,
        reason: "last-owner",
      });
      expect(
        await inScope(scope, (bound) =>
          setTenantMemberRole(bound, owner, "admin"),
        ),
      ).toEqual({
        ok: false,
        reason: "last-owner",
      });
    });

    it("permits removing an owner once a second exists", async () => {
      const scope = await newTenant();
      const first = await newAdmin(db, `admin-${unique()}@example.org`);
      const second = await newAdmin(db, `admin-${unique()}@example.org`);
      await inScope(scope, (bound) =>
        setTenantMemberRole(bound, first, "owner"),
      );
      await inScope(scope, (bound) =>
        setTenantMemberRole(bound, second, "owner"),
      );

      const removal = await inScope(scope, (bound) =>
        removeTenantMember(bound, first),
      );
      expect(removal.ok).toBe(true);
      expect(
        await inScope(scope, (bound) => removeTenantMember(bound, first)),
      ).toEqual({
        ok: false,
        reason: "not-a-member",
      });
    });
  });

  describe("signing keys", () => {
    it("promotes the next key and retires the outgoing one", async () => {
      const fixture = await newFixture();
      expect(
        await withTenantScope(db, fixture.endpointScope, (bound) =>
          promoteNextEndpointKey(bound),
        ),
      ).toEqual({
        ok: false,
        reason: "no-next-key",
      });

      await withTenantScope(db, fixture.endpointScope, (bound) =>
        insertEndpointKey(bound, {
          kid: "kid-1",
          algorithm: "ES384",
          publicJwk: { kty: "EC" },
          privateJwkEncrypted: "envelope-1",
        }),
      );
      const first = await withTenantScope(db, fixture.endpointScope, (bound) =>
        promoteNextEndpointKey(bound),
      );
      expect(first.ok).toBe(true);
      const afterFirst = await withTenantScope(
        db,
        fixture.endpointScope,
        (bound) => getActiveEndpointKey(bound),
      );
      expect(afterFirst?.kid).toBe("kid-1");

      await withTenantScope(db, fixture.endpointScope, (bound) =>
        insertEndpointKey(bound, {
          kid: "kid-2",
          algorithm: "ES384",
          publicJwk: { kty: "EC" },
          privateJwkEncrypted: "envelope-2",
        }),
      );
      const second = expectOk(
        await withTenantScope(db, fixture.endpointScope, (bound) =>
          promoteNextEndpointKey(bound),
        ),
      );
      expect(second.activated.kid).toBe("kid-2");
      expect(second.retired.map((key) => key.kid)).toEqual(["kid-1"]);
      const afterSecond = await withTenantScope(
        db,
        fixture.endpointScope,
        (bound) => getActiveEndpointKey(bound),
      );
      expect(afterSecond?.kid).toBe("kid-2");
    });
  });

  describe("client registration requests", () => {
    it("approves once, creating and linking one client", async () => {
      const fixture = await newFixture();
      const request = await withTenantScope(
        db,
        fixture.endpointScope,
        (bound) =>
          createClientRequest(bound, {
            requestedByEmail: "dev@example.org",
            payload: {
              name: "Requested app",
              clientType: "public",
              redirectUris: ["https://app.example.org/cb"],
              requestedScopes: ["patient/*.rs"],
              contactEmail: "dev@example.org",
            },
          }),
      );

      const approval = await withTenantScope(
        db,
        fixture.endpointScope,
        (bound) =>
          approveClientRequest(
            bound,
            request.id,
            { reviewerId: null, decisionNote: "Looks fine" },
            {
              clientId: `client-${unique()}`,
              name: "Requested app",
              clientType: "public",
              grantTypes: ["authorization_code"],
              redirectUris: ["https://app.example.org/cb"],
            },
          ),
      );

      const approved = expectOk(approval);
      expect(approved.request.status).toBe("approved");
      expect(approved.request.resultingClientId).toBe(approved.client.id);

      const again = await withTenantScope(db, fixture.endpointScope, (bound) =>
        approveClientRequest(
          bound,
          request.id,
          { reviewerId: null },
          {
            clientId: `client-${unique()}`,
            name: "Duplicate",
            clientType: "public",
            grantTypes: ["authorization_code"],
          },
        ),
      );
      expect(again).toEqual({ ok: false, reason: "already-decided" });
    });
  });

  describe("access tokens", () => {
    it("introspects with the OAuth client identifier, before and after revocation", async () => {
      const fixture = await newFixture();
      const jti = `jti-${unique()}`;
      const expiresAt = new Date(Date.now() + 300_000);
      await recordAccessToken(db, fixture.clientScope, {
        jti,
        subject: "user-1",
        scope: "patient/Observation.rs",
        issuer: "https://signet.example.org/t/x/e/y",
        audience: "https://fhir.example.org/fhir",
        launchContext: { patient: "Patient/1" },
        expiresAt,
      });

      const introspected = await introspectAccessToken(
        db,
        fixture.endpointScope,
        jti,
      );
      expect(introspected?.clientId).toBe(fixture.clientScope.clientId);
      expect(introspected?.launchContext).toEqual({ patient: "Patient/1" });
      expect(introspected?.revokedAt).toBeNull();
      expect(introspected?.expiresAt).toBe(
        Math.floor(expiresAt.getTime() / 1000),
      );

      expect(await revokeAccessToken(db, fixture.endpointScope, jti)).toBe(
        true,
      );
      // Idempotent: the second call reports that nothing live was revoked.
      expect(await revokeAccessToken(db, fixture.endpointScope, jti)).toBe(
        false,
      );

      // Still introspectable - a revoked token has to be answerable, or a resource
      // server could not tell it from a token that was never issued.
      const afterwards = await introspectAccessToken(
        db,
        fixture.endpointScope,
        jti,
      );
      expect(afterwards?.revokedAt).not.toBeNull();
    });

    it("does not introspect another endpoint's token", async () => {
      const mine = await newFixture();
      const theirs = await newFixture();
      const jti = `jti-${unique()}`;
      await recordAccessToken(db, theirs.clientScope, {
        jti,
        subject: "user-1",
        scope: "patient/Observation.rs",
        issuer: "https://signet.example.org/t/other/e/y",
        audience: "https://fhir.example.org/fhir",
        expiresAt: new Date(Date.now() + 300_000),
      });

      expect(
        await introspectAccessToken(db, mine.endpointScope, jti),
      ).toBeUndefined();
      expect(await revokeAccessToken(db, mine.endpointScope, jti)).toBe(false);
    });
  });

  describe("consents", () => {
    it("returns only live consents", async () => {
      const fixture = await newFixture();
      const user = await withTenantScope(db, fixture.endpointScope, (bound) =>
        createEndUser(bound, {
          username: `alice-${unique()}`,
          displayName: "Alice",
        }),
      );

      const live = await recordConsent(db, fixture.clientScope, {
        endUserId: user.id,
        scope: "patient/Observation.rs",
      });
      await recordConsent(db, fixture.clientScope, {
        endUserId: user.id,
        scope: "patient/*.cruds",
        expiresAt: new Date(Date.now() - 1000),
      });

      const listed = await listLiveConsents(db, fixture.clientScope, user.id);
      expect(listed.map((consent) => consent.id)).toEqual([live.id]);

      expect(await revokeConsent(db, fixture.endpointScope, live.id)).toBe(
        true,
      );
      expect(
        await listLiveConsents(db, fixture.clientScope, user.id),
      ).toHaveLength(0);
    });
  });

  describe("personas", () => {
    it("offers personas only on a non-production endpoint", async () => {
      const fixture = await newFixture({ isProduction: false });
      const endpoint = await withTenantScope(db, fixture.tenantScope, (bound) =>
        getEndpoint(bound, fixture.endpointScope.endpointId),
      );
      expect(endpoint).toBeDefined();
      if (endpoint === undefined) {
        return;
      }

      await withTenantScope(db, fixture.endpointScope, (bound) =>
        createEndUser(bound, {
          username: `persona-${unique()}`,
          displayName: "Dr Persona",
          isPersona: true,
        }),
      );
      await withTenantScope(db, fixture.endpointScope, (bound) =>
        createEndUser(bound, {
          username: `local-${unique()}`,
          displayName: "Local account",
          passwordHash: "$argon2id$placeholder",
        }),
      );

      const offered = await withTenantScope(
        db,
        fixture.endpointScope,
        (bound) => listSelectablePersonas(bound, endpoint),
      );
      expect(offered).toHaveLength(1);
      expect(offered[0]?.displayName).toBe("Dr Persona");

      // The same rows, on a production endpoint, must not be selectable.
      expect(
        await withTenantScope(db, fixture.endpointScope, (bound) =>
          listSelectablePersonas(bound, {
            ...endpoint,
            isProduction: true,
          }),
        ),
      ).toHaveLength(0);
    });
  });

  describe("the expiry sweep", () => {
    it("removes expired runtime rows and leaves live ones", async () => {
      const fixture = await newFixture();
      await createLaunchContext(db, fixture.endpointScope, {
        handleHash: `sweep-old-${unique()}`,
        context: {},
        expiresAt: new Date(Date.now() - 1000),
      });
      const liveHandle = `sweep-live-${unique()}`;
      await createLaunchContext(db, fixture.endpointScope, {
        handleHash: liveHandle,
        context: {},
        expiresAt: new Date(Date.now() + 600_000),
      });
      await issueRefreshToken(db, fixture.clientScope, {
        tokenHash: `sweep-refresh-${unique()}`,
        subject: "user-1",
        scope: "patient/Observation.rs",
        expiresAt: new Date(Date.now() - 1000),
      });

      const counts = await sweepExpiredRuntimeRows(db);
      expect(counts.launchContexts).toBeGreaterThanOrEqual(1);
      expect(counts.refreshTokens).toBeGreaterThanOrEqual(1);

      expect(
        await findLaunchContext(db, fixture.endpointScope, liveHandle),
      ).toBeDefined();
    });
  });

  describe("row-level security", () => {
    /** A login-less role that the policies apply to, unlike the owner. */
    const ROLE = RLS_TEST_ROLE;

    beforeAll(async () => {
      // The role and the policies are created by the Vitest global setup, before
      // any worker starts: all of it is DDL, and DDL taking exclusive table locks
      // while another worker holds row locks on the same tables is a deadlock. The
      // fallback covers running this file on its own.
      if (!isTestSchemaReady()) {
        await prepareRowLevelSecurityFixtures(db);
      }
    }, 60_000);

    /** Runs work as the restricted role, scoped to one tenant. */
    async function asTenant<T>(
      scope: TenantScope | undefined,
      work: (tx: Executor) => Promise<T>,
    ): Promise<T> {
      return await db.transaction(async (tx) => {
        await tx.execute(sql.raw(`set local role ${ROLE}`));
        if (scope !== undefined) {
          await tx.execute(
            sql`select set_config(${TENANT_SETTING}, ${scope.tenantId}, true)`,
          );
        }
        return await work(tx);
      });
    }

    it("hides another tenant's rows from a scoped connection", async () => {
      const mine = await newFixture();
      const theirs = await newFixture();

      const visible = await asTenant(mine.tenantScope, async (tx) =>
        tx.select({ id: endpoints.id }).from(endpoints),
      );

      expect(visible.map((row) => row.id)).toEqual([
        mine.endpointScope.endpointId,
      ]);
      expect(visible.map((row) => row.id)).not.toContain(
        theirs.endpointScope.endpointId,
      );
    });

    it("shows nothing at all when the tenant setting is missing", async () => {
      await newFixture();

      // Fail-closed: a query that forgot to declare its tenant sees no rows rather
      // than everyone's.
      const visible = await asTenant(undefined, async (tx) =>
        tx.select({ id: endpoints.id }).from(endpoints),
      );
      expect(visible).toEqual([]);
    });

    it("protects rows two joins from their tenant", async () => {
      const mine = await newFixture();
      const theirs = await newFixture();
      await createLaunchContext(db, theirs.endpointScope, {
        handleHash: `rls-${unique()}`,
        context: {},
        expiresAt: new Date(Date.now() + 600_000),
      });
      await issueRefreshToken(db, theirs.clientScope, {
        tokenHash: `rls-refresh-${unique()}`,
        subject: "user-1",
        scope: "patient/Observation.rs",
        expiresAt: new Date(Date.now() + 600_000),
      });

      const counts = await asTenant(mine.tenantScope, async (tx) => ({
        handles: await tx
          .select({ id: launchContexts.id })
          .from(launchContexts),
        tokens: await tx.select({ id: refreshTokens.id }).from(refreshTokens),
      }));

      expect(counts.handles).toEqual([]);
      expect(counts.tokens).toEqual([]);
    });
  });
});
