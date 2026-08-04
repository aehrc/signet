/**
 * The policies, observed from the role Signet actually serves as.
 *
 * `repositories.integration.test.ts` already proves the policies work: it assumes
 * a restricted role inside a transaction and watches another tenant's rows
 * disappear. What it cannot show is that they constrain *Signet*, because the
 * connection it makes them on is the identity that owns the tables, which Postgres
 * exempts from their policies.
 *
 * This suite connects as the serving role - the same non-owning role a deployment
 * uses - and asserts the three properties that make the guarantee real, for every
 * covered table rather than for a sample of them:
 *
 *   1. An unbound read returns no rows.
 *   2. An unbound insert is refused by the database, not by application code.
 *   3. A bound read returns the declared tenant's rows and nothing else.
 *
 * Two tenants are seeded with exactly one row in every covered table, which is
 * what lets the third assertion be exact: bound to one of them, a covered table
 * shows one row, it is not the other tenant's, and it carries this tenant's own
 * identifiers.
 *
 * The insert attempt reconstructs a row the table already holds rather than
 * inventing one, so the refusal cannot be a not-null or check-constraint failure
 * dressed up as an isolation success: Postgres evaluates those before the policy,
 * and the SQLSTATE the test asserts on distinguishes all three.
 *
 * Skipped unless `SIGNET_TEST_DATABASE_URL` names a throwaway database, in step
 * with the other integration suites.
 *
 * Author: John Grimes
 */

import { eq, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import { fileURLToPath } from "node:url";
import postgres from "postgres";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { recordAuditEvent } from "./audit/record.js";
import { classifyEnforcement, observeEnforcement } from "./enforcement.js";
import { recordAccessToken } from "./repositories/accessTokens.js";
import { createAdminUser } from "./repositories/adminUsers.js";
import { createApiToken } from "./repositories/apiTokens.js";
import { createAuthorizationCode } from "./repositories/authorizationCodes.js";
import { createAuthorizationSession } from "./repositories/authorizationSessions.js";
import { createClientRequest } from "./repositories/clientRequests.js";
import { createClient } from "./repositories/clients.js";
import { recordConsent } from "./repositories/consents.js";
import { insertEndpointKey } from "./repositories/endpointKeys.js";
import { createEndpoint, upsertIdpConfig } from "./repositories/endpoints.js";
import { createEndUser } from "./repositories/endUsers.js";
import { createEndUserSession } from "./repositories/endUserSessions.js";
import { sqlStateOf } from "./repositories/errors.js";
import { createFederationState } from "./repositories/federationStates.js";
import { recordJti } from "./repositories/jtiReplay.js";
import { createLaunchContext } from "./repositories/launchContexts.js";
import { setTenantMemberRole } from "./repositories/members.js";
import {
  createPolicyVersion,
  setClientPolicyOverride,
} from "./repositories/policies.js";
import { issueRefreshToken } from "./repositories/refreshTokens.js";
import {
  clientScopeFromRow,
  endpointScopeFromRow,
  executorFor,
  isBoundScope,
  resolveIssuer,
  resolveTenantScope,
  tenantScopeFromRow,
} from "./repositories/scope.js";
import { createTenant } from "./repositories/tenants.js";
import { currentTenantSetting, RLS_TABLES, withTenantScope } from "./rls.js";
import { tenants } from "./schema/tenancy.js";
import { prepareRowLevelSecurityFixtures } from "./test/rlsRole.js";
import { isTestSchemaReady } from "./test/schemaReady.js";
import { prepareServingRole, servingRoleUrl } from "./test/servingRole.js";

import type { Executor } from "./repositories/executor.js";
import type {
  ClientScope,
  EndpointScope,
  TenantScope,
} from "./repositories/scope.js";
import type { PolicyDocument } from "@signet/core";

const databaseUrl = process.env.SIGNET_TEST_DATABASE_URL;

const describeWithDatabase =
  databaseUrl === undefined ? describe.skip : describe;

const migrationsFolder = fileURLToPath(new URL("../drizzle", import.meta.url));

/** The same lock every suite that may have to migrate takes. */
const MIGRATION_LOCK_KEY = 5_348_464;

/** A minimal but valid policy document. */
const POLICY: PolicyDocument = {
  version: 1,
  scopeGrants: [{ match: "patient/*.rs", allow: true }],
  claimRules: [],
  contextRules: [],
  defaults: { accessTokenTtl: 300, refreshTokenTtl: 2_592_000 },
};

/** One tenant's fixtures: a row in every covered table, and the scopes for it. */
interface Seeded {
  readonly tenantScope: TenantScope;
  readonly endpointScope: EndpointScope;
  readonly clientScope: ClientScope;
  readonly sessionId: string;
}

/** A row as the database renders it, for reconstruction and comparison. */
type RowJson = Record<string, unknown>;

/** A column expected to hold a known identifier. */
type IdentityCheck = readonly [column: string, value: string];

describeWithDatabase("row-level security as the serving role", () => {
  let ownerSql: ReturnType<typeof postgres> | undefined;
  let servingSql: ReturnType<typeof postgres> | undefined;
  let owner: Executor;
  let serving: Executor;
  const createdTenantIds: string[] = [];
  let sequence = 0;
  let mine: Seeded;
  let theirs: Seeded;
  /** One row of each covered table, as each tenant's binding sees it. */
  let myRows: Readonly<Record<string, RowJson>> = {};
  let theirRows: Readonly<Record<string, RowJson>> = {};

  beforeAll(async () => {
    ownerSql = postgres(databaseUrl ?? "", { max: 2, onnotice: () => {} });
    owner = drizzle(ownerSql);

    // Normally all of this was done once by the Vitest global setup, before any
    // worker started. The fallback covers running this file on its own, and takes
    // the same advisory lock so two runs cannot interleave their DDL.
    if (!isTestSchemaReady()) {
      await ownerSql`select pg_advisory_lock(${MIGRATION_LOCK_KEY})`;
      try {
        await migrate(drizzle(ownerSql), { migrationsFolder });
        await prepareRowLevelSecurityFixtures(owner);
        await prepareServingRole(owner);
      } finally {
        await ownerSql`select pg_advisory_unlock(${MIGRATION_LOCK_KEY})`;
      }
    }

    servingSql = postgres(servingRoleUrl(databaseUrl ?? ""), {
      max: 2,
      onnotice: () => {},
    });
    serving = drizzle(servingSql);

    // Seeded with the owning identity: creating the fixtures is not what is under
    // test, and seeding unbound keeps it out of the property being asserted.
    mine = await seed("mine");
    theirs = await seed("theirs");
    myRows = await rowsVisibleTo(mine.tenantScope);
    theirRows = await rowsVisibleTo(theirs.tenantScope);
  }, 120_000);

  afterAll(async () => {
    // Cascades through every tenant-owned table, so the suite leaves the shared
    // database as it found it without truncating anything.
    for (const id of createdTenantIds) {
      await owner.delete(tenants).where(eq(tenants.id, id));
    }
    await ownerSql?.end();
    await servingSql?.end();
  });

  /** A distinct suffix, so slugs and digests never collide across runs. */
  function unique(): string {
    sequence += 1;
    return `${Date.now().toString(36)}-${sequence}`;
  }

  /** Ten minutes from now, for anything carrying an expiry. */
  function soon(): Date {
    return new Date(Date.now() + 600_000);
  }

  /**
   * Creates one row in every covered table for a new tenant.
   *
   * Written with the repository functions rather than as raw inserts so the
   * fixture cannot drift from the schema without failing to compile.
   */
  async function seed(label: string): Promise<Seeded> {
    const tenant = await createTenant(owner, {
      slug: `rls-${label}-${unique()}`,
      name: "Enforcement test tenant",
    });
    createdTenantIds.push(tenant.id);
    const tenantScope = tenantScopeFromRow(tenant);

    // `admin_users` is exempt from the policies, so this row is shared ground
    // rather than part of what is asserted. `tenant_members` is not exempt.
    const admin = await createAdminUser(owner, {
      email: `rls-${label}-${unique()}@example.org`,
      passwordHash: "$argon2id$placeholder",
      displayName: "Admin",
    });
    await setTenantMemberRole(owner, tenantScope, admin.id, "owner");
    await createApiToken(owner, tenantScope, {
      name: "Personal access token",
      tokenHash: `api-${unique()}`,
      role: "owner",
      createdBy: admin.id,
      expiresAt: soon(),
    });

    const endpoint = await createEndpoint(owner, tenantScope, {
      slug: `e-${unique()}`,
      name: "Endpoint",
      fhirBaseUrl: "https://fhir.example.org/fhir",
    });
    const endpointScope = endpointScopeFromRow(tenantScope, endpoint);

    await insertEndpointKey(owner, endpointScope, {
      kid: `kid-${unique()}`,
      algorithm: "RS384",
      publicJwk: { kty: "RSA", kid: "k" },
      privateJwkEncrypted: "v1:not-a-real-key",
    });
    await upsertIdpConfig(owner, endpointScope, {
      issuer: `https://idp-${unique()}.example.org`,
      clientId: "signet",
    });

    const endUser = await createEndUser(owner, endpointScope, {
      username: `user-${unique()}`,
      displayName: "End user",
    });

    const client = await createClient(owner, endpointScope, {
      clientId: `client-${unique()}`,
      name: "Test app",
      clientType: "public",
      grantTypes: ["authorization_code", "refresh_token"],
    });
    const clientScope = clientScopeFromRow(endpointScope, client);

    await createClientRequest(owner, endpointScope, {
      requestedByEmail: "dev@example.org",
      trackingTokenHash: `track-${unique()}`,
      payload: {
        name: "Requested app",
        clientType: "public",
        redirectUris: ["https://app.example.org/callback"],
        requestedScopes: ["patient/Observation.rs"],
        contactEmail: "dev@example.org",
      },
    });

    await createPolicyVersion(owner, endpointScope, {
      document: POLICY,
      createdBy: admin.id,
      note: "Seeded",
    });
    await setClientPolicyOverride(owner, clientScope, POLICY);

    await createLaunchContext(owner, endpointScope, {
      handleHash: `launch-${unique()}`,
      context: { patient: "Patient/1" },
      expiresAt: soon(),
    });

    const session = await createAuthorizationSession(owner, clientScope, {
      redirectUri: "https://app.example.org/callback",
      expiresAt: soon(),
      requestedScopes: ["patient/Observation.rs"],
    });
    await createAuthorizationCode(owner, endpointScope, session, {
      codeHash: `code-${unique()}`,
      expiresAt: soon(),
    });
    await createFederationState(owner, endpointScope, session, {
      stateHash: `state-${unique()}`,
      nonce: `nonce-${unique()}`,
      codeVerifier: `verifier-${unique()}`,
      expiresAt: soon(),
    });

    await recordAccessToken(owner, clientScope, {
      jti: `jti-${unique()}`,
      subject: endUser.id,
      scope: "patient/Observation.rs",
      issuer: "https://signet.example.org",
      audience: "https://fhir.example.org/fhir",
      expiresAt: soon(),
    });
    await issueRefreshToken(owner, clientScope, {
      tokenHash: `refresh-${unique()}`,
      subject: endUser.id,
      scope: "patient/Observation.rs",
      expiresAt: soon(),
    });
    await recordConsent(owner, clientScope, {
      endUserId: endUser.id,
      scope: "patient/Observation.rs",
      expiresAt: soon(),
    });
    await createEndUserSession(owner, endpointScope, {
      endUserId: endUser.id,
      tokenHash: `session-${unique()}`,
      expiresAt: soon(),
      ip: null,
      userAgent: null,
    });
    await recordJti(owner, clientScope, `assertion-${unique()}`, soon());

    // Non-fatal by design, so a failure here would leave `audit_events` empty
    // rather than throwing: the reachability assertion below is what catches it.
    await recordAuditEvent(owner, {
      tenantId: tenant.id,
      endpointId: endpoint.id,
      actor: { type: "system" },
      action: "endpoint.created",
    });

    return { tenantScope, endpointScope, clientScope, sessionId: session.id };
  }

  /** Reads a table as the serving role, in whatever binding state it is in. */
  async function rowsOf(db: Executor, table: string): Promise<RowJson[]> {
    const rows = (await db.execute(
      sql`select to_jsonb(t) as row from ${sql.identifier(table)} t`,
    )) as unknown as readonly { readonly row: RowJson }[];
    return rows.map((entry) => entry.row);
  }

  /** Every covered table's row, as the serving role sees it bound to a tenant. */
  async function rowsVisibleTo(
    scope: TenantScope,
  ): Promise<Record<string, RowJson>> {
    return await withTenantScope(serving, scope, async (bound) => {
      const captured: Record<string, RowJson> = {};
      for (const table of RLS_TABLES) {
        const rows = await rowsOf(executorFor(bound), table);
        // One row per tenant per table is what the seeding creates, so anything
        // else is either a leak or a fixture that stopped covering this table.
        expect(rows).toHaveLength(1);
        const [row] = rows;
        if (row !== undefined) {
          captured[table] = row;
        }
      }
      return captured;
    });
  }

  /**
   * How a covered table's row names the tenant it belongs to.
   *
   * `client_id` is deliberately not checked generically: on `clients` it is the
   * OAuth identifier and on `idp_configs` it is the upstream provider's, so
   * comparing it against a surrogate key would be wrong on two tables and right
   * on the rest. The three tables whose only route to a tenant is through one of
   * those keys name it explicitly instead.
   */
  function identityOf(table: string): readonly IdentityCheck[] {
    const specific: Readonly<Record<string, readonly IdentityCheck[]>> = {
      tenants: [["id", mine.tenantScope.tenantId]],
      client_policy_overrides: [["client_id", mine.clientScope.clientRowId]],
      jti_replay: [["client_id", mine.clientScope.clientRowId]],
    };

    return (
      specific[table] ?? [
        ["tenant_id", mine.tenantScope.tenantId],
        ["endpoint_id", mine.endpointScope.endpointId],
        ["session_id", mine.sessionId],
      ]
    );
  }

  describe("with no tenant declared", () => {
    it.each(RLS_TABLES)("returns no rows from %s", async (table) => {
      // Fail-closed, from the database: both tenants have a row in this table and
      // the connection that declared nothing sees neither.
      expect(await rowsOf(serving, table)).toEqual([]);
    });

    it.each(RLS_TABLES)("refuses an insert into %s", async (table) => {
      const row = myRows[table];
      expect(row).toBeDefined();

      // The row already exists, so a policy that permitted this would fail on the
      // primary key instead - which is why the assertion is on the SQLSTATE rather
      // than on something merely having gone wrong. 42501 is "new row violates
      // row-level security policy".
      let state: string | undefined;
      try {
        await serving.execute(
          sql`insert into ${sql.identifier(table)} select * from json_populate_record(null::${sql.identifier(table)}, ${JSON.stringify(row)}::json)`,
        );
      } catch (error) {
        state = sqlStateOf(error);
      }

      expect(state).toBe("42501");
    });
  });

  describe("with a tenant declared", () => {
    it("reaches every covered table", () => {
      // Guards the guard: a table missing from the capture would make every
      // assertion below vacuous, and a table nobody granted would present as one.
      expect(Object.keys(myRows).toSorted()).toEqual(
        [...RLS_TABLES].toSorted(),
      );
      expect(Object.keys(theirRows).toSorted()).toEqual(
        [...RLS_TABLES].toSorted(),
      );
    });

    it.each(RLS_TABLES)(
      "shows the declared tenant's row and not the other's in %s",
      (table) => {
        // Each tenant seeded exactly one row here, and `rowsVisibleTo` asserted
        // that one row is all either binding can see - including the rows every
        // other suite sharing this database has created.
        expect(myRows[table]).toBeDefined();
        expect(theirRows[table]).toBeDefined();
        expect(myRows[table]).not.toEqual(theirRows[table]);
      },
    );

    it.each(RLS_TABLES)("shows a row this tenant owns in %s", (table) => {
      const row = myRows[table];
      const checks = identityOf(table).filter(
        (check) => row?.[check[0]] !== undefined && row[check[0]] !== null,
      );

      // A policy wired through the wrong table would satisfy the row count above
      // and fail here.
      expect(checks.length).toBeGreaterThan(0);
      for (const [column, value] of checks) {
        expect(row?.[column]).toBe(value);
      }
    });
  });

  describe("resolution before a tenant is known", () => {
    // These are the reads that cannot be bound, because they are what establishes
    // the binding. As the serving role they must still work - through the
    // privileged routines - and must still refuse an identifier that resolves to
    // nothing, without distinguishing it from somebody else's tenant.

    it("resolves a tenant slug", async () => {
      const resolved = await resolveTenantScope(
        serving,
        mine.tenantScope.tenantSlug,
      );

      expect(resolved?.tenantId).toBe(mine.tenantScope.tenantId);
      expect(resolved?.tenantSlug).toBe(mine.tenantScope.tenantSlug);
    });

    it("returns nothing for a slug that does not resolve", async () => {
      expect(
        await resolveTenantScope(serving, "no-such-tenant"),
      ).toBeUndefined();
    });

    it("hands back a scope with no binding of its own", async () => {
      // The transaction the resolution read on has committed by the time this
      // returns, so a scope claiming to be bound would carry a dead handle. The
      // caller binds it with `withTenantScope` when it comes to use it.
      const resolved = await resolveTenantScope(
        serving,
        mine.tenantScope.tenantSlug,
      );

      expect(resolved).toBeDefined();
      expect(resolved !== undefined && isBoundScope(resolved)).toBe(false);
    });

    it("resolves an issuer's tenant and endpoint together", async () => {
      const resolved = await resolveIssuer(
        serving,
        mine.tenantScope.tenantSlug,
        mine.endpointScope.endpointSlug,
      );

      expect(resolved?.tenant.id).toBe(mine.tenantScope.tenantId);
      expect(resolved?.endpoint.id).toBe(mine.endpointScope.endpointId);
      expect(resolved?.scope.endpointId).toBe(mine.endpointScope.endpointId);
    });

    it("returns nothing when the endpoint belongs to another tenant", async () => {
      // The endpoint exists; the tenant named in the path does not own it. That
      // must read as absent rather than resolving across the boundary.
      expect(
        await resolveIssuer(
          serving,
          mine.tenantScope.tenantSlug,
          theirs.endpointScope.endpointSlug,
        ),
      ).toBeUndefined();
    });

    it("returns nothing for an unknown tenant slug", async () => {
      expect(
        await resolveIssuer(
          serving,
          "no-such-tenant",
          mine.endpointScope.endpointSlug,
        ),
      ).toBeUndefined();
    });
  });

  describe("the declaration itself", () => {
    it("is gone once the transaction that made it ends", async () => {
      // One connection, so the read afterwards is certainly on the connection the
      // declaration was made on: a setting that outlived its transaction would be
      // inherited by the next request to borrow that connection from the pool.
      const single = postgres(servingRoleUrl(databaseUrl ?? ""), {
        max: 1,
        onnotice: () => {},
      });
      try {
        const db = drizzle(single);
        const inside = await withTenantScope(
          db,
          mine.tenantScope,
          async (bound) => await currentTenantSetting(executorFor(bound)),
        );

        expect(inside).toBe(mine.tenantScope.tenantId);
        expect(await currentTenantSetting(db)).toBeNull();
      } finally {
        await single.end();
      }
    });
  });

  describe("observeEnforcement", () => {
    it("finds the serving role subject to the policies", async () => {
      const verdict = classifyEnforcement(await observeEnforcement(serving));

      expect(verdict.outcome).toBe("healthy");
      expect(verdict.tablesVerified).toBe(RLS_TABLES.length);
    });

    it("finds the owning identity exempt", async () => {
      // The check's whole purpose: this is the credential a deployment must not
      // give the server, and it is indistinguishable from a correct one in every
      // other respect.
      const verdict = classifyEnforcement(await observeEnforcement(owner));

      expect(verdict.outcome).toBe("role-exempt");
      expect(verdict.message).toContain(verdict.role);
    });
  });
});
