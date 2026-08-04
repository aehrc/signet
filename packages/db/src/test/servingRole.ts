/**
 * The role the test suite connects as.
 *
 * The policies are only worth anything if the suite runs under them. Once they did
 * not: every suite connected as the identity that owns the tables, which Postgres
 * exempts from their policies, so the policies could have been dropped entirely
 * without a single test noticing.
 *
 * This module makes the serving role the ordinary path rather than a fixture one
 * file opts into. A developer still configures one variable: `globalSetup` uses
 * `SIGNET_TEST_DATABASE_URL` - the owning identity - to migrate, create this
 * role and grant it, and every suite connects on a URL derived from that one by
 * swapping the credential.
 *
 * The role is created with a login and a fixed password. That is not a secret
 * and is not treated as one: it exists only in a throwaway test database, and a
 * generated password would have to be communicated between the global setup and
 * every worker process, which is a mechanism with more ways to go wrong than the
 * problem has.
 *
 * Author: John Grimes
 */

import { sql } from "drizzle-orm";

import { applyServingRolePrivileges } from "../privileges.js";

import type { Executor } from "../repositories/executor.js";

/**
 * The role the suites connect as.
 *
 * Fixed rather than per-worker: the grants are applied once from the global
 * setup, before any worker starts, for the same reason the migrations are - see
 * `./schemaReady.ts`.
 */
export const SERVING_TEST_ROLE = "signet_app_test";

/**
 * Its password.
 *
 * Not a secret. It names a login on a throwaway database that exists for the
 * duration of a test run, and it is in the repository so that the derivation
 * below needs nothing passed to it.
 */
export const SERVING_TEST_PASSWORD = "signet_app_test";

/**
 * Derives the serving connection from the owning one.
 *
 * Only the credential changes: host, port, database and every connection
 * parameter are carried across, because they are how the developer reached the
 * database in the first place. The credential is percent-encoded on the way in,
 * which is the failure `composeDatabaseUrl` in `apps/server/src/config.ts`
 * documents - a userinfo component that is not encoded can terminate early and
 * silently point the connection at a different host.
 *
 * @param ownerUrl - `SIGNET_TEST_DATABASE_URL`, naming the owning identity.
 * @returns The same database, reached as {@link SERVING_TEST_ROLE}.
 * @throws {Error} When the URL cannot be parsed, naming the variable rather than
 *   quoting it: it contains a password.
 * @example
 * ```ts
 * const handle = createDatabase({ url: servingRoleUrl(testDatabaseUrl) });
 * ```
 */
export function servingRoleUrl(ownerUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(ownerUrl);
  } catch {
    throw new Error("SIGNET_TEST_DATABASE_URL is not a valid connection URL");
  }

  parsed.username = encodeURIComponent(SERVING_TEST_ROLE);
  parsed.password = encodeURIComponent(SERVING_TEST_PASSWORD);
  return parsed.toString();
}

/**
 * Creates the serving role and grants it what the suites need.
 *
 * Idempotent, so a second run over the same database is a no-op rather than an
 * error - which is what lets a developer run the suite repeatedly. Called from
 * the global setup, before any worker starts, because `create role` and
 * `grant ... on all tables` are catalogue writes that should not race with the
 * suites they exist to enable.
 *
 * The role is created plainly: no `bypassrls`, no membership of the owning role,
 * and it owns nothing, because everything it can reach was created by the owner
 * and granted to it here. Those three facts are what the startup check verifies
 * on a real deployment, and the suite is only evidence if they hold here too.
 *
 * @param db - A connection with authority to create roles and grant on the
 *   tables, which in practice is the owning identity.
 */
export async function prepareServingRole(db: Executor): Promise<void> {
  await db.execute(
    sql.raw(`
      do $$
      begin
        if not exists (select 1 from pg_roles where rolname = '${SERVING_TEST_ROLE}') then
          create role ${SERVING_TEST_ROLE} login password '${SERVING_TEST_PASSWORD}';
        end if;
      end
      $$;
    `),
  );

  await applyServingRolePrivileges(db, SERVING_TEST_ROLE);
}
