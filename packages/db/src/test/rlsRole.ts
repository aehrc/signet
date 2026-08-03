/**
 * Preparing the database for the row-level security suite.
 *
 * That suite needs two things that ordinary tests do not: a login-less role the
 * policies actually apply to (the table owner bypasses them, which is why every
 * other suite is unaffected by RLS being enabled), and the policies themselves.
 *
 * Both are DDL. `create role`, `grant … on all tables` and `alter table … enable
 * row level security` each take an exclusive lock, and running them while other
 * workers hold row locks on the same tables is a deadlock Postgres resolves by
 * killing one of the two. So this runs once, from the global setup, before any
 * worker starts — and the policies are then simply left in place, which is also
 * what a deployment looks like.
 */

import { sql } from "drizzle-orm";

import { applyRowLevelSecurity } from "../rls.js";

import type { Executor } from "../repositories/executor.js";

/**
 * The role the row-level security suite acts as.
 *
 * Login-less: it is assumed with `set local role` inside a transaction, never
 * connected as, so it needs no password and cannot be used from outside.
 */
export const RLS_TEST_ROLE = "signet_rls_test";

/**
 * Creates the test role and enables the tenant isolation policies.
 *
 * Idempotent, so a second run over the same database is a no-op rather than an
 * error — which is what lets a developer run the suite repeatedly.
 *
 * @param db - A connection with authority to create roles and alter tables.
 */
export async function prepareRowLevelSecurityFixtures(
  db: Executor,
): Promise<void> {
  await db.execute(
    sql.raw(`
      do $$
      begin
        if not exists (select 1 from pg_roles where rolname = '${RLS_TEST_ROLE}') then
          create role ${RLS_TEST_ROLE} nologin;
        end if;
      end
      $$;
    `),
  );
  await db.execute(
    sql.raw(
      `grant select, insert, update, delete on all tables in schema public to ${RLS_TEST_ROLE}`,
    ),
  );
  await db.execute(sql.raw(`grant usage on schema public to ${RLS_TEST_ROLE}`));
  // Granted to the connecting user so that `set local role` is permitted; the
  // suite has to be able to become the restricted role to observe the policies.
  await db.execute(sql.raw(`grant ${RLS_TEST_ROLE} to current_user`));

  await applyRowLevelSecurity(db);
}
