/**
 * The privileged surface, as the deployed database actually grants it.
 *
 * `privileges.test.ts` asserts the generated statements are right and would keep
 * passing if nothing ever ran them. `privileges.migration.test.ts` asserts the
 * routines are in the migration folder and hardened. Neither asks the database
 * what the serving role can do, and that is the only question a reviewer wanting
 * to know the size of the exemption is actually asking.
 *
 * So this suite asks it, of the role every other suite connects as, and it asks
 * in the two directions that matter:
 *
 *   1. **The surface is exactly the declared set.** Not "every declared routine is
 *      executable" - that would pass with a fourth routine granted beside them.
 *      Every routine in the schema the role may execute is compared against
 *      `PRIVILEGED_ROUTINES`, so widening the exemption fails here rather than
 *      being noticed by somebody reading a migration.
 *   2. **The exemption is the only one.** A role holding `BYPASSRLS`, owning a
 *      covered table, or belonging to a role that owns one is exempt from every
 *      policy while looking correct in every other respect. Three routines are a
 *      bounded exemption only if the role has no unbounded one.
 *
 * The second half of the suite covers the mistake that would quietly turn a
 * resolver into a cross-tenant read: a `language sql` parameter sharing a name
 * with a column resolves in favour of the column, so `where slug = slug` matches
 * every row. `privileges.migration.test.ts` reads the `p_` prefix out of the SQL;
 * this asserts the consequence, with two tenants populated, because a routine
 * that over-returns is indistinguishable from a correct one until there is a
 * second tenant for it to leak.
 *
 * Author: John Grimes
 */

import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import { fileURLToPath } from "node:url";
import postgres from "postgres";

import { PRIVILEGED_ROUTINES } from "./privileges.js";
import { createAdminUser } from "./repositories/adminUsers.js";
import { createApiToken } from "./repositories/apiTokens.js";
import { setTenantMemberRole } from "./repositories/members.js";
import {
  tenantIdForApiTokenDigest,
  tenantIdForSlug,
  tenantIdsForAdminUser,
} from "./repositories/routines.js";
import { tenantScopeFromRow } from "./repositories/scope.js";
import { createTenant } from "./repositories/tenants.js";
import { RLS_TABLES, withTenantScope } from "./rls.js";
import { adminUsers, tenants } from "./schema/tenancy.js";
import {
  listExecutableRoutines,
  ownedCoveredTables,
  roleBypassesPolicies,
} from "./test/privilegeProbe.js";
import { isTestSchemaReady } from "./test/schemaReady.js";
import {
  prepareServingRole,
  SERVING_TEST_ROLE,
  servingRoleUrl,
} from "./test/servingRole.js";

import type { Executor } from "./repositories/executor.js";
import type { TenantScope } from "./repositories/scope.js";

const databaseUrl = process.env.SIGNET_TEST_DATABASE_URL;

const describeWithDatabase =
  databaseUrl === undefined ? describe.skip : describe;

const migrationsFolder = fileURLToPath(new URL("../drizzle", import.meta.url));

/** The same lock every suite that may have to migrate takes. */
const MIGRATION_LOCK_KEY = 5_348_464;

/** One tenant's fixtures: what each routine is given, and what it must return. */
interface Seeded {
  readonly scope: TenantScope;
  readonly slug: string;
  readonly tokenDigest: string;
  readonly adminUserId: string;
}

describeWithDatabase("the serving role's privileged surface", () => {
  let ownerSql: ReturnType<typeof postgres> | undefined;
  let servingSql: ReturnType<typeof postgres> | undefined;
  let owner: Executor;
  let serving: Executor;
  const createdTenantIds: string[] = [];
  const createdAdminIds: string[] = [];
  let sequence = 0;
  let mine: Seeded;
  let theirs: Seeded;

  beforeAll(async () => {
    ownerSql = postgres(databaseUrl ?? "", { max: 2, onnotice: () => {} });
    owner = drizzle(ownerSql);

    // Normally the preload did all of this once, before any test file was imported.
    // The fallback covers running this file on its own, and takes the same advisory
    // lock so two runs cannot interleave their DDL.
    if (!isTestSchemaReady()) {
      await ownerSql`select pg_advisory_lock(${MIGRATION_LOCK_KEY})`;
      try {
        await migrate(drizzle(ownerSql), { migrationsFolder });
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

    mine = await seed("mine");
    theirs = await seed("theirs");
  });

  afterAll(async () => {
    // Cascades through every tenant-owned table, so the suite leaves the shared
    // database as it found it.
    for (const id of createdTenantIds) {
      await owner.delete(tenants).where(eq(tenants.id, id));
    }
    // `admin_users` is exempt from the policies and hangs off no tenant, so the
    // cascade above does not reach it.
    for (const id of createdAdminIds) {
      await owner.delete(adminUsers).where(eq(adminUsers.id, id));
    }
    await ownerSql?.end();
    await servingSql?.end();
  });

  /** A distinct suffix, so slugs and digests never collide across runs. */
  function unique(): string {
    sequence += 1;
    return `${Date.now().toString(36)}-${String(process.pid)}-${sequence}`;
  }

  /**
   * A tenant with exactly one input for each routine.
   *
   * Seeded with the owning identity: creating the fixtures is not what is under
   * test, and the routines are then called as the serving role, which is.
   */
  async function seed(label: string): Promise<Seeded> {
    const slug = `priv-${label}-${unique()}`;
    const tenant = await createTenant(owner, {
      slug,
      name: "Privilege test tenant",
    });
    createdTenantIds.push(tenant.id);

    const admin = await createAdminUser(owner, {
      email: `priv-${label}-${unique()}@example.org`,
      passwordHash: "$argon2id$placeholder",
      displayName: "Admin",
    });
    createdAdminIds.push(admin.id);

    // Built from the row the insert returned, which is the only way to obtain one.
    const scope = tenantScopeFromRow(tenant);
    await withTenantScope(owner, scope, (bound) =>
      setTenantMemberRole(bound, admin.id, "owner"),
    );

    const tokenDigest = `priv-token-${unique()}`;
    await withTenantScope(owner, scope, (bound) =>
      createApiToken(bound, {
        name: "Personal access token",
        tokenHash: tokenDigest,
        role: "owner",
        createdBy: admin.id,
        expiresAt: new Date(Date.now() + 600_000),
      }),
    );

    return { scope, slug, tokenDigest, adminUserId: admin.id };
  }

  describe("is exactly the declared set", () => {
    it("grants execute on the declared routines and no others", async () => {
      // The assertion is an equality rather than a per-routine `true`, which is
      // what makes a fourth routine granted beside these three a failure here.
      expect(await listExecutableRoutines(owner, SERVING_TEST_ROLE)).toEqual(
        Object.keys(PRIVILEGED_ROUTINES).toSorted(),
      );
    });
  });

  describe("holds no exemption beyond it", () => {
    it("does not hold BYPASSRLS", async () => {
      // Exempt from every policy on every table, and invisible in a schema diff.
      expect(await roleBypassesPolicies(owner, SERVING_TEST_ROLE)).toBe(false);
    });

    it("owns no covered table, directly or through membership", async () => {
      // Postgres exempts a table's owner, and membership of the owning role
      // inherits that exemption - which is why this asks `pg_has_role` rather
      // than comparing the role's name against each table's owner.
      expect(
        await ownedCoveredTables(owner, SERVING_TEST_ROLE, RLS_TABLES),
      ).toEqual([]);
    });
  });

  describe("each routine returns only the tenant its input names", () => {
    it("resolves a slug to that tenant alone", async () => {
      expect(await tenantIdForSlug(serving, mine.slug)).toBe(
        mine.scope.tenantId,
      );
      expect(await tenantIdForSlug(serving, theirs.slug)).toBe(
        theirs.scope.tenantId,
      );
    });

    it("resolves a token digest to that tenant alone", async () => {
      expect(await tenantIdForApiTokenDigest(serving, mine.tokenDigest)).toBe(
        mine.scope.tenantId,
      );
      expect(await tenantIdForApiTokenDigest(serving, theirs.tokenDigest)).toBe(
        theirs.scope.tenantId,
      );
    });

    it("returns only the tenants an admin user belongs to", async () => {
      // The widest hole this feature could open. A parameter named `admin_user_id`
      // rather than `p_admin_user_id` would be resolved in favour of the column,
      // making the predicate a tautology and this routine a list of every tenant
      // in the deployment - handed to any signed-in console user.
      expect(await tenantIdsForAdminUser(serving, mine.adminUserId)).toEqual([
        mine.scope.tenantId,
      ]);
      expect(await tenantIdsForAdminUser(serving, theirs.adminUserId)).toEqual([
        theirs.scope.tenantId,
      ]);
    });
  });

  describe("discloses nothing for an input that does not resolve", () => {
    it("returns nothing for an unknown slug", async () => {
      // Absent must be indistinguishable from somebody else's, or an
      // unauthenticated caller can enumerate tenant slugs.
      expect(
        await tenantIdForSlug(serving, `absent-${unique()}`),
      ).toBeUndefined();
    });

    it("returns nothing for an unknown token digest", async () => {
      expect(
        await tenantIdForApiTokenDigest(serving, `absent-${unique()}`),
      ).toBeUndefined();
    });

    it("returns an empty set for an admin user with no memberships", async () => {
      const stranger = await createAdminUser(owner, {
        email: `priv-stranger-${unique()}@example.org`,
        passwordHash: "$argon2id$placeholder",
        displayName: "Stranger",
      });
      createdAdminIds.push(stranger.id);

      expect(await tenantIdsForAdminUser(serving, stranger.id)).toEqual([]);
    });

    it("returns an empty set for an admin user that does not exist", async () => {
      expect(
        await tenantIdsForAdminUser(
          serving,
          "00000000-0000-0000-0000-000000000000",
        ),
      ).toEqual([]);
    });
  });
});
