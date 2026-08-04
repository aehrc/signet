/**
 * The `migrate` command, against a real database.
 *
 * This is the test that matters for the serving role's privileges, and the
 * reason is recorded in the header of `packages/db/src/rls.migration.test.ts`:
 * the failure that suite exists to catch was a generator producing perfect SQL
 * that nothing ever ran. `privileges.test.ts` asserts the statements are right
 * and would keep passing if `runMigrateCommand` never issued one of them.
 *
 * So the assertions below are made against the database rather than against a
 * string. They ask what the role may actually do, through `has_table_privilege`
 * and `has_function_privilege`, after the command has been run exactly as a Helm
 * hook Job would run it.
 *
 * Author: John Grimes
 */

import {
  createDatabase,
  createProbeRole,
  dropProbeRole,
  listSignetRoutines,
  PRIVILEGED_ROUTINES,
  RLS_TABLES,
  roleCanExecute,
  roleHasDefaultTablePrivileges,
  roleHasTablePrivilege,
} from "@signet/db";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { runMigrateCommand } from "./migrate.js";
import { testDatabaseUrl } from "./test/harness.js";

import type { Database, DatabaseHandle } from "@signet/db";

/**
 * A throwaway serving role, unique to this worker.
 *
 * Login-less, because nothing here connects as it: the question is what it is
 * permitted to do, which `has_*_privilege` answers without a session.
 */
const SERVING_ROLE = `signet_migrate_test_${String(process.pid)}`;

describe.skipIf(testDatabaseUrl === undefined)(
  "the migrate command's grants",
  () => {
    let handle: DatabaseHandle;
    let db: Database;

    beforeAll(async () => {
      handle = createDatabase({
        url: testDatabaseUrl ?? "",
        maxConnections: 1,
      });
      db = handle.db;
      await createProbeRole(db, SERVING_ROLE);

      // Exactly as the Helm hook Job invokes it: the owning identity applies the
      // migrations, and the serving role is named rather than connected as.
      await runMigrateCommand(
        testDatabaseUrl ?? "",
        SERVING_ROLE,
        () => undefined,
      );
    });

    afterAll(async () => {
      await dropProbeRole(db, SERVING_ROLE);
      await handle.close();
    });

    it("installs the privileged routines", async () => {
      expect(await listSignetRoutines(db)).toEqual(
        Object.keys(PRIVILEGED_ROUTINES).toSorted(),
      );
    });

    it.each(Object.keys(PRIVILEGED_ROUTINES))(
      "lets the serving role execute %s",
      async (routine) => {
        expect(await roleCanExecute(db, SERVING_ROLE, routine)).toBe(true);
      },
    );

    it.each(Object.keys(PRIVILEGED_ROUTINES))(
      "does not leave %s executable by public",
      async (routine) => {
        // Every role is a member of PUBLIC, so without the revoke in the
        // migration the grant above would be decoration and every role in the
        // deployment could resolve any tenant.
        expect(await roleCanExecute(db, "public", routine)).toBe(false);
      },
    );

    it.each(RLS_TABLES)(
      "makes %s reachable by the serving role",
      async (table) => {
        // Reachable, not visible. The policies decide what rows come back;
        // without the grant a correctly bound query fails with a permission
        // error, which is a different failure from the empty result a missing
        // policy produces.
        expect(
          await roleHasTablePrivilege(db, SERVING_ROLE, table, "select"),
          `${table} select`,
        ).toBe(true);
        expect(
          await roleHasTablePrivilege(db, SERVING_ROLE, table, "insert"),
          `${table} insert`,
        ).toBe(true);
      },
    );

    it("leaves the audit trail append-only", async () => {
      // The constitution's append-only requirement, enforced by privilege rather
      // than by convention. Insert must survive the revoke, or nothing can be
      // audited at all.
      expect(
        await roleHasTablePrivilege(db, SERVING_ROLE, "audit_events", "insert"),
      ).toBe(true);
      expect(
        await roleHasTablePrivilege(db, SERVING_ROLE, "audit_events", "update"),
      ).toBe(false);
      expect(
        await roleHasTablePrivilege(db, SERVING_ROLE, "audit_events", "delete"),
      ).toBe(false);
    });

    it("sets default privileges so a later table cannot ship ungranted", async () => {
      expect(await roleHasDefaultTablePrivileges(db, SERVING_ROLE)).toBe(true);
    });

    it("is idempotent, as a re-run hook Job requires", async () => {
      await expect(
        runMigrateCommand(testDatabaseUrl ?? "", SERVING_ROLE, () => undefined),
      ).resolves.toBeUndefined();

      expect(
        await roleHasTablePrivilege(db, SERVING_ROLE, "tenants", "select"),
      ).toBe(true);
    });
  },
);
