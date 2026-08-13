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
 * Every call is made as the serving role, which the tenant isolation policies
 * apply to. That matters for what these tests mean: with the owning identity they
 * would pass whether or not a policy were installed, because Postgres exempts a
 * table's owner. The owning identity appears in two places only - creating the
 * schema, and the expiry sweep, which is cross-tenant by design and has its own
 * tests below.
 *
 * Skipped unless `SIGNET_TEST_DATABASE_URL` names a throwaway database. CI has none
 * yet, and a suite that connected regardless would fail the build.
 *
 * Every test creates its own tenants and deletes them afterwards rather than
 * truncating: the tables are shared with every other suite in the run and with a
 * second `bun test` against the same database, and a suite that emptied them would
 * break both.
 *
 * Author: John Grimes
 */

import { MAX_PASSKEYS_PER_ACCOUNT } from "@signet/core";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "bun:test";
import { eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import { fileURLToPath } from "node:url";
import postgres from "postgres";

import { withTenantScope } from "../rls.js";
import {
  introspectAccessToken,
  recordAccessToken,
  revokeAccessToken,
} from "./accessTokens.js";
import {
  consumeAdminPasskeyChallenge,
  createAdminPasskeyChallenge,
  deleteExpiredAdminPasskeyChallenges,
  findAdminPasskeyByCredentialId,
  insertAdminPasskey,
  listAdminPasskeys,
  recordAdminPasskeyUse,
  removeAdminPasskey,
} from "./adminPasskeys.js";
import { createAdminUser } from "./adminUsers.js";
import {
  consumeAuthorizationCode,
  createAuthorizationCode,
  findAuthorizationCode,
} from "./authorizationCodes.js";
import { createAuthorizationSession } from "./authorizationSessions.js";
import { approveClientRequest, createClientRequest } from "./clientRequests.js";
import {
  createClient,
  createVouchedClient,
  getClientByClientId,
  resolveClientScope,
} from "./clients.js";
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
  resolveIssuer,
  tenantScopeFromRow,
  TenantScopeViolationError,
} from "./scope.js";
import { sweepExpiredRuntimeRows } from "./sweep.js";
import { createTenant } from "./tenants.js";
import {
  deleteEndpointTicketIssuer,
  deleteEndpointTrustAnchor,
  getEndpointTicketIssuer,
  getEndpointTrustAnchor,
  upsertEndpointTicketIssuer,
  upsertEndpointTrustAnchor,
} from "./trust.js";
import { clients } from "../schema/clients.js";
import { tenants } from "../schema/tenancy.js";
import { isTestSchemaReady } from "../test/schemaReady.js";
import { prepareServingRole, servingRoleUrl } from "../test/servingRole.js";

import type { AdminPasskeyInput } from "./adminPasskeys.js";
import type { updateClient } from "./clients.js";
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

/**
 * The vouching trio is written once and never edited.
 *
 * A compile-time assertion rather than a runtime one, because that is where the
 * guarantee lives: `updateClient`'s patch type does not name these columns, so an
 * edit to a client's anchor, statement or expiry does not compile. `tsc --build`
 * checks this whether or not a test database is configured, which a skipped
 * integration test would not.
 */
type ClientPatch = Parameters<typeof updateClient>[1];
export const VOUCHING_IS_NOT_PATCHABLE: [
  Extract<
    keyof ClientPatch,
    "vouchedByIssuer" | "vouchedStatementId" | "vouchingExpiresAt"
  >,
] extends [never]
  ? true
  : false = true;

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
  return await withTenantScope(db, fixture.clientScope, (bound) =>
    issueRefreshToken(bound, {
      tokenHash,
      subject: "user-1",
      scope: "patient/Observation.rs",
      expiresAt,
    }),
  );
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
  let ownerSql: ReturnType<typeof postgres> | undefined;
  let connection: ReturnType<typeof drizzle>;
  let db: Executor;
  /** The owning identity; see `beforeAll`. */
  let owner: Executor;
  const createdTenantIds: string[] = [];
  let sequence = 0;

  beforeAll(async () => {
    // The owning identity, kept for the schema, for the fixture teardown that
    // cascades across tenants, and for the sweep's own tests. Nothing this file
    // asserts on is issued through it.
    ownerSql = postgres(databaseUrl ?? "", { max: 2, onnotice: () => {} });
    const ownerConnection = drizzle(ownerSql);
    owner = ownerConnection;

    // See the audit suite: the schema is normally already there, migrated once by
    // the preload before any test file was imported.
    if (!isTestSchemaReady()) {
      await ownerSql`select pg_advisory_lock(${MIGRATION_LOCK_KEY})`;
      try {
        await migrate(ownerConnection, { migrationsFolder });
        await prepareServingRole(owner);
      } finally {
        await ownerSql`select pg_advisory_unlock(${MIGRATION_LOCK_KEY})`;
      }
    }

    // Every repository call below is made as the serving role - the same
    // non-owning role a deployment uses - so the results are the results the
    // policies permit rather than the results the owner is exempt from.
    sql_ = postgres(servingRoleUrl(databaseUrl ?? ""), {
      max: 5,
      onnotice: () => {},
    });
    connection = drizzle(sql_);

    // `drizzle(sql)` and `Executor` differ in a phantom schema type parameter
    // only; the query surface used here is identical.
    db = connection as unknown as Executor;
  });

  afterEach(async () => {
    // Cascades through every tenant-owned table, so each test starts clean without
    // truncating anything a parallel suite might be using. Issued as the owner:
    // deleting several tenants is cross-tenant work, and the point of the suite is
    // that the serving role cannot do it.
    while (createdTenantIds.length > 0) {
      const id = createdTenantIds.pop();
      if (id !== undefined) {
        await owner.delete(tenants).where(eq(tenants.id, id));
      }
    }
  });

  afterAll(async () => {
    await sql_?.end();
    await ownerSql?.end();
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
    return await withTenantScope(db, fixture.clientScope, (bound) =>
      createAuthorizationSession(bound, {
        redirectUri: "https://app.example.org/callback",
        expiresAt: new Date(Date.now() + 600_000),
        requestedScopes: ["patient/Observation.rs"],
      }),
    );
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
      await withTenantScope(db, fixture.endpointScope, (bound) =>
        createAuthorizationCode(bound, session, {
          codeHash: "code-hash-1",
          expiresAt: new Date(Date.now() + 60_000),
        }),
      );

      const first = await withTenantScope(db, fixture.endpointScope, (bound) =>
        consumeAuthorizationCode(bound, "code-hash-1"),
      );
      const claimed = expectOk(first);
      expect(claimed.session.id).toBe(session.id);
      expect(claimed.code.consumedAt).not.toBeNull();

      const second = await withTenantScope(db, fixture.endpointScope, (bound) =>
        consumeAuthorizationCode(bound, "code-hash-1"),
      );
      expect(second).toEqual({ ok: false, reason: "already-consumed" });
    });

    it("lets exactly one of two overlapping redemptions win", async () => {
      const fixture = await newFixture();
      const session = await newSession(fixture);
      await withTenantScope(db, fixture.endpointScope, (bound) =>
        createAuthorizationCode(bound, session, {
          codeHash: "code-hash-race",
          expiresAt: new Date(Date.now() + 60_000),
        }),
      );

      const [first, second] = await raceOnOneRow((executor) =>
        withTenantScope(executor, fixture.endpointScope, (bound) =>
          consumeAuthorizationCode(bound, "code-hash-race"),
        ),
      );

      expect(first.ok).toBe(true);
      expect(second).toEqual({ ok: false, reason: "already-consumed" });
    });

    it("refuses an expired code without consuming it", async () => {
      const fixture = await newFixture();
      const session = await newSession(fixture);
      await withTenantScope(db, fixture.endpointScope, (bound) =>
        createAuthorizationCode(bound, session, {
          codeHash: "code-hash-old",
          expiresAt: new Date(Date.now() - 1000),
        }),
      );

      const result = await withTenantScope(db, fixture.endpointScope, (bound) =>
        consumeAuthorizationCode(bound, "code-hash-old"),
      );
      expect(result).toEqual({ ok: false, reason: "expired" });
    });

    it("cannot redeem another endpoint's code, and leaves it unconsumed", async () => {
      const mine = await newFixture();
      const theirs = await newFixture();
      const session = await newSession(theirs);
      await withTenantScope(db, theirs.endpointScope, (bound) =>
        createAuthorizationCode(bound, session, {
          codeHash: "code-hash-foreign",
          expiresAt: new Date(Date.now() + 60_000),
        }),
      );

      const result = await withTenantScope(db, mine.endpointScope, (bound) =>
        consumeAuthorizationCode(bound, "code-hash-foreign"),
      );
      expect(result).toEqual({ ok: false, reason: "not-found" });

      // The important half: the attempt must not have spent the victim's code.
      const untouched = await withTenantScope(
        db,
        theirs.endpointScope,
        (bound) => findAuthorizationCode(bound, "code-hash-foreign"),
      );
      expect(untouched?.consumedAt).toBeNull();
    });

    it("refuses a code minted against another endpoint's session", async () => {
      const mine = await newFixture();
      const theirs = await newFixture();
      const session = await newSession(theirs);

      await expect(
        withTenantScope(db, mine.endpointScope, (bound) =>
          createAuthorizationCode(bound, session, {
            codeHash: "code-hash-mismatch",
            expiresAt: new Date(Date.now() + 60_000),
          }),
        ),
      ).rejects.toThrow(TenantScopeViolationError);
    });
  });

  describe("launch handles", () => {
    it("redeems a bound handle once, for the client it was bound to", async () => {
      const fixture = await newFixture();
      await withTenantScope(db, fixture.endpointScope, (bound) =>
        createLaunchContext(bound, {
          handleHash: "launch-1",
          context: { patient: "Patient/1" },
          expiresAt: new Date(Date.now() + 60_000),
          boundTo: fixture.clientScope,
        }),
      );

      const first = await withTenantScope(db, fixture.clientScope, (bound) =>
        consumeLaunchContext(bound, "launch-1"),
      );
      expect(expectOk(first).launch.context).toEqual({ patient: "Patient/1" });

      expect(
        await withTenantScope(db, fixture.clientScope, (bound) =>
          consumeLaunchContext(bound, "launch-1"),
        ),
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

      await withTenantScope(db, fixture.endpointScope, (bound) =>
        createLaunchContext(bound, {
          handleHash: "launch-bound",
          context: { patient: "Patient/2" },
          expiresAt: new Date(Date.now() + 60_000),
          boundTo: fixture.clientScope,
        }),
      );

      expect(
        await withTenantScope(db, otherScope, (bound) =>
          consumeLaunchContext(bound, "launch-bound"),
        ),
      ).toEqual({ ok: false, reason: "client-mismatch" });

      const untouched = await withTenantScope(
        db,
        fixture.endpointScope,
        (bound) => findLaunchContext(bound, "launch-bound"),
      );
      expect(untouched?.consumedAt).toBeNull();
    });

    it("lets any client redeem an unbound handle", async () => {
      const fixture = await newFixture();
      await withTenantScope(db, fixture.endpointScope, (bound) =>
        createLaunchContext(bound, {
          handleHash: "launch-open",
          context: {},
          expiresAt: new Date(Date.now() + 60_000),
        }),
      );

      const redemption = await withTenantScope(
        db,
        fixture.clientScope,
        (bound) => consumeLaunchContext(bound, "launch-open"),
      );
      expect(redemption.ok).toBe(true);
    });

    it("refuses to bind a handle to a client from another endpoint", async () => {
      const mine = await newFixture();
      const theirs = await newFixture();

      await expect(
        withTenantScope(db, mine.endpointScope, (bound) =>
          createLaunchContext(bound, {
            handleHash: "launch-foreign",
            context: {},
            expiresAt: new Date(Date.now() + 60_000),
            boundTo: theirs.clientScope,
          }),
        ),
      ).rejects.toThrow(TenantScopeViolationError);
    });
  });

  describe("refresh token rotation", () => {
    it("rotates into the same family and links the predecessor", async () => {
      const fixture = await newFixture();
      const original = await issueRefresh(db, fixture, "refresh-a");

      const rotation = await withTenantScope(db, fixture.clientScope, (bound) =>
        redeemAndRotateRefreshToken(bound, "refresh-a", {
          tokenHash: "refresh-b",
          scope: "patient/Observation.rs",
          expiresAt: new Date(Date.now() + 600_000),
        }),
      );

      expect(rotation.ok).toBe(true);
      if (!rotation.ok) {
        return;
      }
      expect(rotation.replacement.familyId).toBe(original.familyId);
      expect(rotation.replacement.subject).toBe("user-1");

      const predecessor = await withTenantScope(
        db,
        fixture.endpointScope,
        (bound) => findRefreshToken(bound, "refresh-a"),
      );
      expect(predecessor?.revokedAt).not.toBeNull();
      expect(predecessor?.replacedById).toBe(rotation.replacement.id);
    });

    it("revokes the whole family when a rotated token is presented again", async () => {
      const fixture = await newFixture();
      await issueRefresh(db, fixture, "refresh-1");
      const rotation = await withTenantScope(db, fixture.clientScope, (bound) =>
        redeemAndRotateRefreshToken(bound, "refresh-1", {
          tokenHash: "refresh-2",
          scope: "patient/Observation.rs",
          expiresAt: new Date(Date.now() + 600_000),
        }),
      );
      expect(rotation.ok).toBe(true);

      const reuse = await withTenantScope(db, fixture.endpointScope, (bound) =>
        redeemRefreshToken(bound, "refresh-1"),
      );
      expect(reuse.ok).toBe(false);
      if (reuse.ok) {
        return;
      }
      expect(reuse.reason).toBe("reused");
      // The successor was live; detecting the theft must have killed it.
      expect(reuse.familyRevoked).toBe(1);

      const successor = await withTenantScope(
        db,
        fixture.endpointScope,
        (bound) => findRefreshToken(bound, "refresh-2"),
      );
      expect(successor?.revokedAt).not.toBeNull();

      // And the successor now reads as revoked rather than as reused: it has no
      // successor of its own, so it is not evidence of a second theft.
      const afterwards = await withTenantScope(
        db,
        fixture.endpointScope,
        (bound) => redeemRefreshToken(bound, "refresh-2"),
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
        withTenantScope(executor, fixture.endpointScope, (bound) =>
          redeemRefreshToken(bound, "refresh-race"),
        ),
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
      await withTenantScope(db, fixture.clientScope, (bound) =>
        issueRefreshToken(bound, {
          tokenHash: "refresh-old",
          subject: "user-1",
          scope: "patient/Observation.rs",
          expiresAt: new Date(Date.now() - 1000),
        }),
      );

      expect(
        await withTenantScope(db, fixture.endpointScope, (bound) =>
          redeemRefreshToken(bound, "refresh-old"),
        ),
      ).toEqual({ ok: false, reason: "expired", familyRevoked: 0 });
    });

    it("will not rotate another client's token into this client's family", async () => {
      const mine = await newFixture();
      const theirs = await newFixture();
      const foreign = await issueRefresh(db, theirs, "refresh-foreign");

      await expect(
        withTenantScope(db, mine.clientScope, (bound) =>
          rotateRefreshToken(bound, foreign, {
            tokenHash: "refresh-stolen",
            scope: "patient/Observation.rs",
            expiresAt: new Date(Date.now() + 600_000),
          }),
        ),
      ).rejects.toThrow(TenantScopeViolationError);
    });

    it("does not see another endpoint's token", async () => {
      const mine = await newFixture();
      const theirs = await newFixture();
      await issueRefresh(db, theirs, "refresh-elsewhere");

      expect(
        await withTenantScope(db, mine.endpointScope, (bound) =>
          redeemRefreshToken(bound, "refresh-elsewhere"),
        ),
      ).toEqual({ ok: false, reason: "not-found", familyRevoked: 0 });

      const untouched = await withTenantScope(
        db,
        theirs.endpointScope,
        (bound) => findRefreshToken(bound, "refresh-elsewhere"),
      );
      expect(untouched?.revokedAt).toBeNull();
    });
  });

  describe("the jti replay ledger", () => {
    it("accepts an assertion once and refuses it thereafter", async () => {
      const fixture = await newFixture();
      const expiresAt = new Date(Date.now() + 300_000);

      expect(
        await withTenantScope(db, fixture.clientScope, (bound) =>
          recordJti(bound, "jti-1", expiresAt),
        ),
      ).toEqual({ status: "recorded" });
      expect(
        await withTenantScope(db, fixture.clientScope, (bound) =>
          recordJti(bound, "jti-1", expiresAt),
        ),
      ).toEqual({ status: "already-seen" });
      expect(
        await withTenantScope(db, fixture.clientScope, (bound) =>
          hasSeenJti(bound, "jti-1"),
        ),
      ).toBe(true);
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

      await withTenantScope(db, fixture.clientScope, (bound) =>
        recordJti(bound, "shared-jti", expiresAt),
      );

      // jti values are only unique per issuer, so a second client may legitimately
      // choose the same one.
      expect(
        await withTenantScope(db, otherScope, (bound) =>
          recordJti(bound, "shared-jti", expiresAt),
        ),
      ).toEqual({
        status: "recorded",
      });
    });

    it("leaves the transaction usable after a replay", async () => {
      const fixture = await newFixture();
      const expiresAt = new Date(Date.now() + 300_000);
      await withTenantScope(db, fixture.clientScope, (bound) =>
        recordJti(bound, "jti-tx", expiresAt),
      );

      // A raised unique violation would abort the surrounding transaction and take
      // the rest of the token exchange with it.
      await db.transaction(async (tx) => {
        expect(
          await withTenantScope(tx, fixture.clientScope, (bound) =>
            recordJti(bound, "jti-tx", expiresAt),
          ),
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

  describe("trust rules", () => {
    // Both rules are what turn a refused capability on, so the properties that
    // matter are: the endpoint that has one sees it, an endpoint that has none
    // sees nothing at all, and no endpoint can see another's.

    it("has no trust anchor until one is configured", async () => {
      const fixture = await newFixture();

      // The deny-by-default state. Registration reads this and answers 404.
      expect(
        await inScope(fixture.endpointScope, getEndpointTrustAnchor),
      ).toBeUndefined();
    });

    it("has no ticket issuer until one is configured", async () => {
      const fixture = await newFixture();

      expect(
        await inScope(fixture.endpointScope, getEndpointTicketIssuer),
      ).toBeUndefined();
    });

    it("stores and reads back a trust anchor rule", async () => {
      const fixture = await newFixture();

      const written = await inScope(fixture.endpointScope, (bound) =>
        upsertEndpointTrustAnchor(bound, {
          issuer: "https://anchor.example.org",
          jwksUri: "https://anchor.example.org/jwks",
          maxVouchingDays: 14,
        }),
      );

      expect(written.endpointId).toBe(fixture.endpointScope.endpointId);
      expect(
        await inScope(fixture.endpointScope, getEndpointTrustAnchor),
      ).toEqual(written);
    });

    it("stores and reads back a ticket issuer rule", async () => {
      const fixture = await newFixture();

      const written = await inScope(fixture.endpointScope, (bound) =>
        upsertEndpointTicketIssuer(bound, {
          issuer: "https://tickets.example.org",
          jwksUri: "https://tickets.example.org/jwks",
          acceptedTicketTypes: ["patient-self-access"],
          maxTokenLifetimeSecs: 120,
        }),
      );

      expect(written.acceptedTicketTypes).toEqual(["patient-self-access"]);
      expect(
        await inScope(fixture.endpointScope, getEndpointTicketIssuer),
      ).toEqual(written);
    });

    it("accepts no ticket type unless the rule names one", async () => {
      const fixture = await newFixture();

      const written = await inScope(fixture.endpointScope, (bound) =>
        upsertEndpointTicketIssuer(bound, {
          issuer: "https://tickets.example.org",
          jwksUri: "https://tickets.example.org/jwks",
        }),
      );

      // A rule that exists but names no type grants nothing, which is the only
      // safe reading of a half-configured rule.
      expect(written.acceptedTicketTypes).toEqual([]);
    });

    it("replaces a trust anchor rather than adding a second", async () => {
      const fixture = await newFixture();
      await inScope(fixture.endpointScope, (bound) =>
        upsertEndpointTrustAnchor(bound, {
          issuer: "https://first.example.org",
          jwksUri: "https://first.example.org/jwks",
        }),
      );

      const replaced = await inScope(fixture.endpointScope, (bound) =>
        upsertEndpointTrustAnchor(bound, {
          issuer: "https://second.example.org",
          jwksUri: "https://second.example.org/jwks",
          maxVouchingDays: 7,
        }),
      );

      // One rule per endpoint, decided by the primary key: an endpoint trusting
      // two anchors at once is not something the code has to choose between.
      expect(replaced.issuer).toBe("https://second.example.org");
      expect(replaced.maxVouchingDays).toBe(7);
      expect(
        (await inScope(fixture.endpointScope, getEndpointTrustAnchor))?.issuer,
      ).toBe("https://second.example.org");
    });

    it("removes a trust anchor, returning the endpoint to refusal", async () => {
      const fixture = await newFixture();
      await inScope(fixture.endpointScope, (bound) =>
        upsertEndpointTrustAnchor(bound, {
          issuer: "https://anchor.example.org",
          jwksUri: "https://anchor.example.org/jwks",
        }),
      );

      expect(
        await inScope(fixture.endpointScope, deleteEndpointTrustAnchor),
      ).toBe(true);
      expect(
        await inScope(fixture.endpointScope, getEndpointTrustAnchor),
      ).toBeUndefined();
      // Removing a rule that is not there is not an error: the caller wanted the
      // endpoint to have no anchor, and it has none.
      expect(
        await inScope(fixture.endpointScope, deleteEndpointTrustAnchor),
      ).toBe(false);
    });

    it("removes a ticket issuer, returning the endpoint to refusal", async () => {
      const fixture = await newFixture();
      await inScope(fixture.endpointScope, (bound) =>
        upsertEndpointTicketIssuer(bound, {
          issuer: "https://tickets.example.org",
          jwksUri: "https://tickets.example.org/jwks",
          acceptedTicketTypes: ["patient-self-access"],
        }),
      );

      expect(
        await inScope(fixture.endpointScope, deleteEndpointTicketIssuer),
      ).toBe(true);
      expect(
        await inScope(fixture.endpointScope, getEndpointTicketIssuer),
      ).toBeUndefined();
      expect(
        await inScope(fixture.endpointScope, deleteEndpointTicketIssuer),
      ).toBe(false);
    });

    it("never shows one endpoint's rules to another", async () => {
      const mine = await newFixture();
      const theirs = await newFixture();
      await inScope(mine.endpointScope, (bound) =>
        upsertEndpointTrustAnchor(bound, {
          issuer: "https://mine.example.org",
          jwksUri: "https://mine.example.org/jwks",
        }),
      );

      // Two tenants, so both layers are in play: the endpoint predicate and the
      // policy. The other endpoint's read must come back empty rather than with
      // a rule it did not configure.
      expect(
        await inScope(theirs.endpointScope, getEndpointTrustAnchor),
      ).toBeUndefined();
      expect(
        await inScope(theirs.endpointScope, deleteEndpointTrustAnchor),
      ).toBe(false);
      expect(
        (await inScope(mine.endpointScope, getEndpointTrustAnchor))?.issuer,
      ).toBe("https://mine.example.org");
    });
  });

  describe("vouched clients", () => {
    /** The vouching a registration would write, with a fresh statement id. */
    function vouching(statementId: string) {
      return {
        vouchedByIssuer: "https://anchor.example.org",
        vouchedStatementId: statementId,
        vouchingExpiresAt: new Date(Date.now() + 86_400_000),
      };
    }

    it("records the anchor, the statement and the expiry together", async () => {
      const fixture = await newFixture();
      const statementId = `stmt-${unique()}`;

      const client = await inScope(fixture.endpointScope, (bound) =>
        createVouchedClient(
          bound,
          {
            clientId: `vouched-${unique()}`,
            name: "Vouched app",
            clientType: "public",
            grantTypes: ["authorization_code"],
          },
          vouching(statementId),
        ),
      );

      expect(client.vouchedByIssuer).toBe("https://anchor.example.org");
      expect(client.vouchedStatementId).toBe(statementId);
      expect(client.vouchingExpiresAt).not.toBeNull();
    });

    it("lets one statement vouch for exactly one registration", async () => {
      const fixture = await newFixture();
      const statementId = `stmt-${unique()}`;
      const register = () =>
        inScope(fixture.endpointScope, (bound) =>
          createVouchedClient(
            bound,
            {
              clientId: `vouched-${unique()}`,
              name: "Vouched app",
              clientType: "public",
              grantTypes: ["authorization_code"],
            },
            vouching(statementId),
          ),
        );

      await register();

      // The unique constraint is what arbitrates two registrations racing with
      // the same statement: the second insert cannot succeed, so exactly one
      // client exists no matter how the two interleave.
      await expect(register()).rejects.toThrow();
    });

    it("lets the same statement id exist on a different endpoint", async () => {
      const mine = await newFixture();
      const theirs = await newFixture();
      const statementId = `stmt-${unique()}`;
      const register = (fixture: Fixture) =>
        inScope(fixture.endpointScope, (bound) =>
          createVouchedClient(
            bound,
            {
              clientId: `vouched-${unique()}`,
              name: "Vouched app",
              clientType: "public",
              grantTypes: ["authorization_code"],
            },
            vouching(statementId),
          ),
        );

      // The ledger is per endpoint, because `jti` values are only unique per
      // issuer: a global constraint would refuse a second endpoint's legitimate
      // registration as a replay.
      await register(mine);
      await expect(register(theirs)).resolves.toBeDefined();
    });

    it("leaves an ordinary client unvouched", async () => {
      const fixture = await newFixture();

      const client = await inScope(fixture.endpointScope, (bound) =>
        createClient(bound, {
          clientId: `portal-${unique()}`,
          name: "Portal app",
          clientType: "public",
          grantTypes: ["authorization_code"],
        }),
      );

      // Three nulls, and the trio is what "vouched" means - so a portal-created
      // client can never be mistaken for one an anchor vouched for.
      expect(client.vouchedByIssuer).toBeNull();
      expect(client.vouchedStatementId).toBeNull();
      expect(client.vouchingExpiresAt).toBeNull();
    });

    it("never shows one endpoint's vouched client to another", async () => {
      const mine = await newFixture();
      const theirs = await newFixture();
      const clientId = `vouched-${unique()}`;
      await inScope(mine.endpointScope, (bound) =>
        createVouchedClient(
          bound,
          {
            clientId,
            name: "Vouched app",
            clientType: "public",
            grantTypes: ["authorization_code"],
          },
          vouching(`stmt-${unique()}`),
        ),
      );

      expect(
        await inScope(theirs.endpointScope, (bound) =>
          getClientByClientId(bound, clientId),
        ),
      ).toBeUndefined();
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
      await withTenantScope(db, fixture.clientScope, (bound) =>
        recordAccessToken(bound, {
          jti,
          subject: "user-1",
          scope: "patient/Observation.rs",
          issuer: "https://signet.example.org/t/x/e/y",
          audience: "https://fhir.example.org/fhir",
          launchContext: { patient: "Patient/1" },
          expiresAt,
        }),
      );

      const introspected = await withTenantScope(
        db,
        fixture.endpointScope,
        (bound) => introspectAccessToken(bound, jti),
      );
      expect(introspected?.clientId).toBe(fixture.clientScope.clientId);
      expect(introspected?.launchContext).toEqual({ patient: "Patient/1" });
      expect(introspected?.revokedAt).toBeNull();
      expect(introspected?.expiresAt).toBe(
        Math.floor(expiresAt.getTime() / 1000),
      );

      expect(
        await withTenantScope(db, fixture.endpointScope, (bound) =>
          revokeAccessToken(bound, jti),
        ),
      ).toBe(true);
      // Idempotent: the second call reports that nothing live was revoked.
      expect(
        await withTenantScope(db, fixture.endpointScope, (bound) =>
          revokeAccessToken(bound, jti),
        ),
      ).toBe(false);

      // Still introspectable - a revoked token has to be answerable, or a resource
      // server could not tell it from a token that was never issued.
      const afterwards = await withTenantScope(
        db,
        fixture.endpointScope,
        (bound) => introspectAccessToken(bound, jti),
      );
      expect(afterwards?.revokedAt).not.toBeNull();
    });

    it("does not introspect another endpoint's token", async () => {
      const mine = await newFixture();
      const theirs = await newFixture();
      const jti = `jti-${unique()}`;
      await withTenantScope(db, theirs.clientScope, (bound) =>
        recordAccessToken(bound, {
          jti,
          subject: "user-1",
          scope: "patient/Observation.rs",
          issuer: "https://signet.example.org/t/other/e/y",
          audience: "https://fhir.example.org/fhir",
          expiresAt: new Date(Date.now() + 300_000),
        }),
      );

      expect(
        await withTenantScope(db, mine.endpointScope, (bound) =>
          introspectAccessToken(bound, jti),
        ),
      ).toBeUndefined();
      expect(
        await withTenantScope(db, mine.endpointScope, (bound) =>
          revokeAccessToken(bound, jti),
        ),
      ).toBe(false);
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

      const live = await withTenantScope(db, fixture.clientScope, (bound) =>
        recordConsent(bound, {
          endUserId: user.id,
          scope: "patient/Observation.rs",
        }),
      );
      await withTenantScope(db, fixture.clientScope, (bound) =>
        recordConsent(bound, {
          endUserId: user.id,
          scope: "patient/*.cruds",
          expiresAt: new Date(Date.now() - 1000),
        }),
      );

      const listed = await withTenantScope(db, fixture.clientScope, (bound) =>
        listLiveConsents(bound, user.id),
      );
      expect(listed.map((consent) => consent.id)).toEqual([live.id]);

      expect(
        await withTenantScope(db, fixture.endpointScope, (bound) =>
          revokeConsent(bound, live.id),
        ),
      ).toBe(true);
      expect(
        await withTenantScope(db, fixture.clientScope, (bound) =>
          listLiveConsents(bound, user.id),
        ),
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

  describe("the redemption boundary", () => {
    it("keeps a redeemed token revoked when its successor cannot be issued", async () => {
      // SC-007. Claiming a refresh token and issuing its successor are separate
      // units, and the ordering is what makes theft detectable: the token is spent
      // the instant it is accepted, so a second presentation cannot claim it
      // whatever happens next. Sharing one transaction would undo that - a failure
      // during issuance would roll the claim back and leave the token unspent - so
      // this fails if anybody consolidates the two.
      const fixture = await newFixture();
      const presented = `refresh-boundary-${unique()}`;
      await issueRefresh(db, fixture, presented);

      const redemption = await inScope(fixture.endpointScope, (bound) =>
        redeemRefreshToken(bound, presented),
      );
      const claimed = expectOk(redemption);

      // The successor reuses the predecessor's digest, which the unique index
      // refuses. A forced failure rather than a mocked one: what is being asserted
      // is the transaction boundary, and only a real statement can cross it.
      await expect(
        inScope(fixture.clientScope, (bound) =>
          rotateRefreshToken(bound, claimed.token, {
            tokenHash: presented,
            scope: "patient/Observation.rs",
            expiresAt: new Date(Date.now() + 600_000),
          }),
        ),
      ).rejects.toThrow();

      const after = await inScope(fixture.endpointScope, (bound) =>
        findRefreshToken(bound, presented),
      );

      // A revoked leaf and no successor. The user must reauthorise, which is
      // inconvenient and correct; an unspent token would be neither.
      expect(after?.revokedAt).not.toBeNull();
      expect(after?.replacedById).toBeNull();
    });
  });

  describe("the expiry sweep", () => {
    // The sweep is the one thing in this file that needs the owning identity, and
    // `db` is deliberately not it: the suite connects as the serving role, so a
    // test that used `db` here would be asserting the converse below rather than
    // the sweep itself.

    /** One expired launch handle, one live one, and one expired refresh token. */
    async function seedForSweep(): Promise<{
      readonly fixture: Fixture;
      readonly liveHandle: string;
    }> {
      const fixture = await newFixture();
      await withTenantScope(db, fixture.endpointScope, (bound) =>
        createLaunchContext(bound, {
          handleHash: `sweep-old-${unique()}`,
          context: {},
          expiresAt: new Date(Date.now() - 1000),
        }),
      );
      const liveHandle = `sweep-live-${unique()}`;
      await withTenantScope(db, fixture.endpointScope, (bound) =>
        createLaunchContext(bound, {
          handleHash: liveHandle,
          context: {},
          expiresAt: new Date(Date.now() + 600_000),
        }),
      );
      await withTenantScope(db, fixture.clientScope, (bound) =>
        issueRefreshToken(bound, {
          tokenHash: `sweep-refresh-${unique()}`,
          subject: "user-1",
          scope: "patient/Observation.rs",
          expiresAt: new Date(Date.now() - 1000),
        }),
      );
      return { fixture, liveHandle };
    }

    it("affects no tenant-owned rows when the serving role attempts it", async () => {
      // The converse of the test below, and the reason it is safe for the serving
      // role to be able to call the sweep at all. The policies hide every row from
      // a connection that has declared no tenant, so a cross-tenant delete issued
      // by the serving role deletes nothing rather than some of it - there is no
      // partial outcome to reason about.
      const { fixture, liveHandle } = await seedForSweep();

      const counts = await sweepExpiredRuntimeRows(db);

      // Every tenant-owned table, named one at a time rather than compared as a
      // whole object. The sweep also reaches two tables the policies exempt -
      // `admin_sessions` and `admin_passkey_challenges`, both of which hang off a
      // person rather than a tenant - and the serving role can delete from those,
      // correctly. Asserting zero for them would be asserting something this test
      // does not claim, and would fail the moment another suite in the run left an
      // expired challenge behind.
      expect({
        launchContexts: counts.launchContexts,
        authorizationCodes: counts.authorizationCodes,
        authorizationSessions: counts.authorizationSessions,
        accessTokens: counts.accessTokens,
        refreshTokens: counts.refreshTokens,
        consents: counts.consents,
        jtiReplay: counts.jtiReplay,
        endUserSessions: counts.endUserSessions,
      }).toEqual({
        launchContexts: 0,
        authorizationCodes: 0,
        authorizationSessions: 0,
        accessTokens: 0,
        refreshTokens: 0,
        consents: 0,
        jtiReplay: 0,
        endUserSessions: 0,
      });

      // And the expired rows it could not see are still there for the owner to
      // sweep, so the empty result was the policies rather than an empty database.
      expect(
        await withTenantScope(db, fixture.endpointScope, (bound) =>
          findLaunchContext(bound, liveHandle),
        ),
      ).toBeDefined();
      expect(
        (await sweepExpiredRuntimeRows(owner)).launchContexts,
      ).toBeGreaterThanOrEqual(1);
    });

    it("removes expired runtime rows and leaves live ones", async () => {
      const fixture = await newFixture();
      await withTenantScope(db, fixture.endpointScope, (bound) =>
        createLaunchContext(bound, {
          handleHash: `sweep-old-${unique()}`,
          context: {},
          expiresAt: new Date(Date.now() - 1000),
        }),
      );
      const liveHandle = `sweep-live-${unique()}`;
      await withTenantScope(db, fixture.endpointScope, (bound) =>
        createLaunchContext(bound, {
          handleHash: liveHandle,
          context: {},
          expiresAt: new Date(Date.now() + 600_000),
        }),
      );
      await withTenantScope(db, fixture.clientScope, (bound) =>
        issueRefreshToken(bound, {
          tokenHash: `sweep-refresh-${unique()}`,
          subject: "user-1",
          scope: "patient/Observation.rs",
          expiresAt: new Date(Date.now() - 1000),
        }),
      );

      const counts = await sweepExpiredRuntimeRows(owner);
      expect(counts.launchContexts).toBeGreaterThanOrEqual(1);
      expect(counts.refreshTokens).toBeGreaterThanOrEqual(1);

      expect(
        await withTenantScope(db, fixture.endpointScope, (bound) =>
          findLaunchContext(bound, liveHandle),
        ),
      ).toBeDefined();
    });
  });

  describe("passkeys", () => {
    /** Registers a passkey with fields nothing else in the run will collide on. */
    async function register(
      adminUserId: string,
      overrides: Partial<AdminPasskeyInput> = {},
    ) {
      return await insertAdminPasskey(db, {
        adminUserId,
        credentialId: `cred-${unique()}`,
        publicKey: `key-${unique()}`,
        counter: 0,
        transports: ["internal"],
        name: "Test key",
        ...overrides,
      });
    }

    it("lists an account's own passkeys and nobody else's", async () => {
      const mine = await newAdmin(db, `pk-${unique()}@example.org`);
      const theirs = await newAdmin(db, `pk-${unique()}@example.org`);
      await register(mine, { name: "First" });
      await register(mine, { name: "Second" });
      await register(theirs, { name: "Not mine" });

      const listed = await listAdminPasskeys(db, mine);

      // Oldest first, because the list is read as a history of what was added.
      expect(listed.map((passkey) => passkey.name)).toEqual([
        "First",
        "Second",
      ]);
    });

    it("refuses a credential identifier already registered to another account", async () => {
      // The identifier is what sign-in resolves an account *from*, so two accounts
      // claiming one credential would make that resolution ambiguous.
      const first = await newAdmin(db, `pk-${unique()}@example.org`);
      const second = await newAdmin(db, `pk-${unique()}@example.org`);
      const credentialId = `shared-${unique()}`;

      expect((await register(first, { credentialId })).ok).toBe(true);
      expect(await register(second, { credentialId })).toEqual({
        ok: false,
        reason: "already-registered",
      });
    });

    it("refuses an eleventh passkey on one account", async () => {
      const adminUserId = await newAdmin(db, `pk-${unique()}@example.org`);
      for (let index = 0; index < MAX_PASSKEYS_PER_ACCOUNT; index += 1) {
        expect((await register(adminUserId)).ok).toBe(true);
      }

      expect(await register(adminUserId)).toEqual({
        ok: false,
        reason: "cap-reached",
      });
      expect(await listAdminPasskeys(db, adminUserId)).toHaveLength(
        MAX_PASSKEYS_PER_ACCOUNT,
      );
    });

    it("counts the cap per account rather than across the table", async () => {
      const full = await newAdmin(db, `pk-${unique()}@example.org`);
      const other = await newAdmin(db, `pk-${unique()}@example.org`);
      for (let index = 0; index < MAX_PASSKEYS_PER_ACCOUNT; index += 1) {
        await register(full);
      }

      // A cap that counted rows rather than the account's rows would refuse this.
      expect((await register(other)).ok).toBe(true);
    });

    it("resolves a credential identifier to its passkey and its owner", async () => {
      const adminUserId = await newAdmin(db, `pk-${unique()}@example.org`);
      const credentialId = `find-${unique()}`;
      await register(adminUserId, { credentialId, name: "Findable" });

      const found = await findAdminPasskeyByCredentialId(db, credentialId);

      expect(found?.passkey.name).toBe("Findable");
      // The account comes back with it: sign-in has to know whether it is
      // disabled, and one query is one decision.
      expect(found?.user.id).toBe(adminUserId);
    });

    it("answers nothing for a credential identifier nobody registered", async () => {
      expect(
        await findAdminPasskeyByCredentialId(db, `absent-${unique()}`),
      ).toBeUndefined();
    });

    it("advances a counter that moved forward, and stamps the last use", async () => {
      const adminUserId = await newAdmin(db, `pk-${unique()}@example.org`);
      const created = expectOk(await register(adminUserId, { counter: 4 }));
      const at = new Date();

      expect(await recordAdminPasskeyUse(db, created.passkey.id, 5, at)).toBe(
        true,
      );

      const [stored] = await listAdminPasskeys(db, adminUserId);
      expect(stored?.counter).toBe(5);
      expect(stored?.lastUsedAt).not.toBeNull();
    });

    it("stamps the last use of an authenticator that always reports zero", async () => {
      // The iCloud Keychain case. Refusing the update because the counter did not
      // advance would leave "last used" permanently blank for most authenticators.
      const adminUserId = await newAdmin(db, `pk-${unique()}@example.org`);
      const created = expectOk(await register(adminUserId, { counter: 0 }));

      expect(
        await recordAdminPasskeyUse(db, created.passkey.id, 0, new Date()),
      ).toBe(true);

      const [stored] = await listAdminPasskeys(db, adminUserId);
      expect(stored?.counter).toBe(0);
      expect(stored?.lastUsedAt).not.toBeNull();
    });

    it("refuses a counter that did not move forward", async () => {
      const adminUserId = await newAdmin(db, `pk-${unique()}@example.org`);
      const created = expectOk(await register(adminUserId, { counter: 9 }));

      expect(
        await recordAdminPasskeyUse(db, created.passkey.id, 9, new Date()),
      ).toBe(false);
      expect(
        await recordAdminPasskeyUse(db, created.passkey.id, 8, new Date()),
      ).toBe(false);

      const [stored] = await listAdminPasskeys(db, adminUserId);
      expect(stored?.counter).toBe(9);
      // Nothing was recorded at all, so a refused sign-in leaves no trace of use.
      expect(stored?.lastUsedAt).toBeNull();
    });

    it("removes a passkey only for the account that owns it", async () => {
      const owner_ = await newAdmin(db, `pk-${unique()}@example.org`);
      const stranger = await newAdmin(db, `pk-${unique()}@example.org`);
      const created = expectOk(await register(owner_));

      // Scoped to the owner, so another account's identifier is simply not found -
      // which is also what stops the API disclosing that it exists.
      expect(await removeAdminPasskey(db, stranger, created.passkey.id)).toBe(
        false,
      );
      expect(await listAdminPasskeys(db, owner_)).toHaveLength(1);

      expect(await removeAdminPasskey(db, owner_, created.passkey.id)).toBe(
        true,
      );
      expect(await listAdminPasskeys(db, owner_)).toHaveLength(0);
      // And a second removal is not a second success.
      expect(await removeAdminPasskey(db, owner_, created.passkey.id)).toBe(
        false,
      );
    });

    it("spends a challenge exactly once", async () => {
      const adminUserId = await newAdmin(db, `pk-${unique()}@example.org`);
      const challenge = `chal-${unique()}`;
      await createAdminPasskeyChallenge(db, {
        challenge,
        purpose: "registration",
        adminUserId,
        expiresAt: new Date(Date.now() + 60_000),
      });

      const first = await consumeAdminPasskeyChallenge(
        db,
        challenge,
        "registration",
      );
      expect(first?.adminUserId).toBe(adminUserId);

      // Replay. The row is gone, so the second ceremony has nothing to verify
      // against - which is what makes single use a property of the database
      // rather than of a check somebody could forget.
      expect(
        await consumeAdminPasskeyChallenge(db, challenge, "registration"),
      ).toBeUndefined();
    });

    it("refuses a challenge presented for the other purpose", async () => {
      // A registration challenge is minted behind a password check; accepting it
      // as an authentication challenge would let one be spent for a sign-in.
      const adminUserId = await newAdmin(db, `pk-${unique()}@example.org`);
      const challenge = `chal-${unique()}`;
      await createAdminPasskeyChallenge(db, {
        challenge,
        purpose: "registration",
        adminUserId,
        expiresAt: new Date(Date.now() + 60_000),
      });

      expect(
        await consumeAdminPasskeyChallenge(db, challenge, "authentication"),
      ).toBeUndefined();
      // And it is still there for the ceremony it was minted for.
      expect(
        await consumeAdminPasskeyChallenge(db, challenge, "registration"),
      ).toBeDefined();
    });

    it("refuses a challenge whose window has closed", async () => {
      const challenge = `chal-${unique()}`;
      await createAdminPasskeyChallenge(db, {
        challenge,
        purpose: "authentication",
        adminUserId: null,
        expiresAt: new Date(Date.now() - 1000),
      });

      expect(
        await consumeAdminPasskeyChallenge(db, challenge, "authentication"),
      ).toBeUndefined();
    });

    it("sweeps expired challenges and leaves live ones", async () => {
      const stale = `chal-stale-${unique()}`;
      const live = `chal-live-${unique()}`;
      await createAdminPasskeyChallenge(db, {
        challenge: stale,
        purpose: "authentication",
        adminUserId: null,
        expiresAt: new Date(Date.now() - 1000),
      });
      await createAdminPasskeyChallenge(db, {
        challenge: live,
        purpose: "authentication",
        adminUserId: null,
        expiresAt: new Date(Date.now() + 600_000),
      });

      expect(
        await deleteExpiredAdminPasskeyChallenges(db),
      ).toBeGreaterThanOrEqual(1);

      expect(
        await consumeAdminPasskeyChallenge(db, live, "authentication"),
      ).toBeDefined();
    });

    it("is swept by the scheduled job", async () => {
      // The sweep is where an unconsumed challenge is actually collected in a
      // deployment; a delete function nothing calls would leave the table growing.
      const stale = `chal-swept-${unique()}`;
      await createAdminPasskeyChallenge(db, {
        challenge: stale,
        purpose: "authentication",
        adminUserId: null,
        expiresAt: new Date(Date.now() - 1000),
      });

      expect(
        (await sweepExpiredRuntimeRows(owner)).passkeyChallenges,
      ).toBeGreaterThanOrEqual(1);
    });
  });
});
