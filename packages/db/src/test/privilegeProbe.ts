/**
 * Asking the database what a role is actually permitted to do.
 *
 * The privilege suites cannot assert against the statements they generate - that
 * is what `privileges.test.ts` does, and it would keep passing if nothing ever
 * ran them. They have to ask the database, and asking means raw SQL against the
 * catalogues.
 *
 * Which is why these live here rather than in the suites that use them. Only
 * `@signet/db` depends on Drizzle, deliberately: a second package importing it
 * resolves a second copy, and two copies of a library whose types carry private
 * fields are mutually unassignable. `apps/server/src/migrate.integration.test.ts`
 * has to observe privileges without being able to write `sql` at all, so the
 * observations are exported from the package that can.
 *
 * Author: John Grimes
 */

import { sql } from "drizzle-orm";

import type { Executor } from "../repositories/executor.js";

/** A table privilege Postgres can be asked about by name. */
export type TablePrivilege = "select" | "insert" | "update" | "delete";

/** Reads the single value of a single-column, single-row result. */
async function scalar<T>(db: Executor, query: ReturnType<typeof sql>) {
  const rows = (await db.execute(query)) as unknown as readonly Record<
    string,
    T
  >[];
  const first = rows[0];
  if (first === undefined) {
    throw new Error("expected exactly one row");
  }
  return Object.values(first)[0] as T;
}

/**
 * Whether a role holds a privilege on a table.
 *
 * Answers reachability, not visibility. A role that cannot reach a table fails
 * with a permission error; a role that can reach it but has declared no tenant
 * gets an empty result. Those are different outcomes with different remedies,
 * and a suite that could not distinguish them would report a table nobody
 * granted as a policy working correctly.
 *
 * @param db - A connection that may read the catalogues.
 * @param role - The role to ask about.
 * @param table - The table, unqualified.
 * @param privilege - Which privilege.
 * @returns True when the role holds it, whether directly or through membership.
 */
export async function roleHasTablePrivilege(
  db: Executor,
  role: string,
  table: string,
  privilege: TablePrivilege,
): Promise<boolean> {
  return await scalar<boolean>(
    db,
    sql`select has_table_privilege(${role}, ${table}, ${privilege})`,
  );
}

/**
 * Whether a role may execute a routine, named by its signature.
 *
 * Pass `"public"` to ask whether the pseudo-role every role belongs to may
 * execute it, which is the question the `revoke ... from public` in migration
 * `0007_serving_role_privileges` exists to answer no to.
 *
 * @param db - A connection that may read the catalogues.
 * @param role - The role to ask about, or `"public"`.
 * @param routine - The signature with argument types, as declared in
 *   `PRIVILEGED_ROUTINES` - for example `signet_tenant_id_for_slug(text)`.
 * @returns True when the role may execute it.
 */
export async function roleCanExecute(
  db: Executor,
  role: string,
  routine: string,
): Promise<boolean> {
  return await scalar<boolean>(
    db,
    sql`select has_function_privilege(${role}, ${routine}, 'execute')`,
  );
}

/**
 * Whether the role would be granted access to a table created from now on.
 *
 * The backstop for a migration that adds a table and nobody remembering to grant
 * it. Reads `pg_default_acl` rather than creating a table, because creating one
 * in a shared test database is DDL that would take a lock while other workers
 * are running.
 *
 * @param db - A connection that may read the catalogues.
 * @param role - The role to ask about.
 * @returns True when a default privilege entry for `public` names the role.
 */
export async function roleHasDefaultTablePrivileges(
  db: Executor,
  role: string,
): Promise<boolean> {
  const count = await scalar<string>(
    db,
    sql`
      select count(*)::text
              from pg_default_acl d
              join pg_namespace n on n.oid = d.defaclnamespace
              where n.nspname = 'public'
                and d.defaclobjtype = 'r'
                and array_to_string(d.defaclacl, ',') like ${`%${role}=%`}
    `,
  );
  return Number(count) > 0;
}

/**
 * Every routine Signet installs, by the signature `PRIVILEGED_ROUTINES` uses.
 *
 * `oidvectortypes(proargtypes)` renders argument types only, which is both what
 * `grant execute on function` accepts and how the declaration is keyed - so the
 * two can be compared without either being reformatted to match the other.
 *
 * @param db - A connection that may read the catalogues.
 * @returns The signatures, sorted.
 */
export async function listSignetRoutines(
  db: Executor,
): Promise<readonly string[]> {
  const rows = (await db.execute(
    sql`
      select p.proname || '(' || oidvectortypes(p.proargtypes) || ')' as signature
              from pg_proc p
              join pg_namespace n on n.oid = p.pronamespace
              where n.nspname = 'public' and p.proname like 'signet\_%'
    `,
  )) as unknown as readonly { readonly signature: string }[];

  return rows.map((row) => row.signature).toSorted();
}

/** How a probe role should differ from the login-less default. */
export interface ProbeRoleOptions {
  /**
   * Gives the role a login with this password.
   *
   * Only for a suite that must actually connect as it - the startup check asks
   * about `current_user`, so a role it is to refuse has to be connected as. Not a
   * secret: it names a login on a throwaway database, in step with
   * `./servingRole.ts`.
   */
  readonly password?: string;
  /**
   * Grants `BYPASSRLS`.
   *
   * One of the two exemptions the startup check exists to refuse, and the one that
   * cannot be arranged any other way: ownership comes with creating a table, but a
   * bypass is an attribute somebody granted. Requires the connected role to hold
   * it too, which for a throwaway test database means a superuser.
   */
  readonly bypassesPolicies?: boolean;
}

/**
 * Creates a role for a suite to make assertions about.
 *
 * Login-less by default, because what a role is permitted to do is a question
 * `has_*_privilege` answers without a session, so a password would be a credential
 * invented for no reason. {@link ProbeRoleOptions} covers the suite that needs the
 * opposite.
 *
 * @param db - A connection with authority to create roles.
 * @param role - The name to create. Unique per worker, since Vitest runs files
 *   in parallel against one database.
 * @param options - Deviations from the login-less default.
 */
export async function createProbeRole(
  db: Executor,
  role: string,
  options: ProbeRoleOptions = {},
): Promise<void> {
  const login =
    options.password === undefined
      ? "nologin"
      : `login password '${options.password.replaceAll("'", "''")}'`;
  const bypass = options.bypassesPolicies === true ? " bypassrls" : "";

  await db.execute(
    sql.raw(`create role "${role.replaceAll('"', '""')}" ${login}${bypass}`),
  );
}

/**
 * Drops a probe role and everything granted to it.
 *
 * `drop owned by` first: a role still holding privileges cannot be dropped, and
 * that includes the `alter default privileges` entry naming it.
 *
 * @param db - A connection with authority to drop roles.
 * @param role - The name to drop.
 */
export async function dropProbeRole(db: Executor, role: string): Promise<void> {
  const quoted = `"${role.replaceAll('"', '""')}"`;
  await db.execute(sql.raw(`drop owned by ${quoted}`));
  await db.execute(sql.raw(`drop role ${quoted}`));
}
