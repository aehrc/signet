/**
 * What the serving role is allowed to do.
 *
 * Signet connects as a role the tenant isolation policies apply to, which means
 * every tenant-owned read and write it performs must declare a tenant first. Two
 * kinds of thing are needed to make that workable, and this module holds both.
 *
 * The first is ordinary table access. The policies decide what rows a bound query
 * sees; the grants decide whether it may reach the table at all, and without them
 * a correctly bound query fails with a permission error rather than returning its
 * tenant's rows. Those grants name the serving role, whose name is configuration rather
 * than a constant - an operator chooses it, or a managed database hands one out -
 * so they cannot be static migration SQL. {@link servingRolePrivilegeStatements}
 * generates them and the `migrate` command applies them immediately after the
 * migrations, inside the same advisory lock.
 *
 * The second is the small set of reads that cannot be bound because they are what
 * establishes the tenant in the first place: turning `/t/{slug}` into a tenant,
 * turning a personal access token's digest into a tenant, and answering "which
 * tenants may this console user see". Those go through the `security definer`
 * routines created by migration `0007_serving_role_privileges`, and
 * {@link PRIVILEGED_ROUTINES} is the declared list of them.
 *
 * The list is the point. An exemption of unlimited shape reachable from one
 * module - a second connection on a privileged role, say - is not materially
 * better than the posture this replaces. An exemption that is three routines,
 * each taking an identifier the caller already supplied and returning identifiers
 * only, is something a reviewer can read and a test can compare against the
 * deployed schema. It follows the pattern `RLS_EXEMPT_TABLES` in `./rls.ts`
 * established: a declared list, a justification each, and a test that fails when
 * reality and the list disagree.
 *
 * Author: John Grimes
 */

import { sql } from "drizzle-orm";

import type { Executor } from "./repositories/executor.js";

/**
 * The routines the serving role may execute without having declared a tenant.
 *
 * Keyed by the routine's signature with its argument types, which is both what
 * `grant execute on function` needs and what `oidvectortypes(proargtypes)`
 * produces from `pg_proc` - so the declaration and the deployed schema can be
 * compared without either being reformatted to match the other.
 *
 * Adding an entry here is a deliberate widening of what Signet can do unbound,
 * and it is the only way to widen it: the integration suite asserts the routines
 * the serving role may actually execute equal this set exactly.
 */
export const PRIVILEGED_ROUTINES: Readonly<Record<string, string>> = {
  "signet_tenant_id_for_slug(text)":
    "The tenant slug in /t/{slug} is the only input an incoming OAuth or console request carries, so resolving it necessarily precedes knowing a tenant. Returns one uuid, or NULL for a slug that does not resolve, so a caller cannot tell an absent tenant from somebody else's.",
  "signet_tenant_id_for_api_token(text)":
    "A personal access token is presented with no tenant in the request, and api_tokens is tenant-owned, so the row cannot be found under the policies. Takes the digest rather than the token, so the routine's call history is not replayable.",
  "signet_tenant_ids_for_admin(uuid)":
    "The console's tenant picker answers which tenants a signed-in operator may see, which necessarily precedes choosing one. The only genuinely cross-tenant read the server performs, and it returns tenant ids and nothing else.",
};

/**
 * Quotes an identifier the way Postgres does.
 *
 * An embedded double quote is escaped by doubling it. Emitting the name raw
 * would work for the lower-case name a developer picks and break on the
 * mixed-case one a managed database hands out, and emitting it unescaped would
 * end the identifier early and leave the remainder as SQL.
 */
function quoteIdentifier(name: string): string {
  return `"${name.replaceAll('"', '""')}"`;
}

/**
 * The statements that give a serving role exactly the access Signet needs.
 *
 * Generated rather than written into a migration because every one of them names
 * the role, and the role name is read from the serving connection's URL. The
 * routines themselves name nobody, so they live in migration
 * `0007_serving_role_privileges` where they can be reviewed as SQL.
 *
 * Order matters in one place: the blanket table grant is issued before the
 * `audit_events` revoke, because a revoke issued first would simply be undone by
 * the grant, and the two orderings look identical in a diff.
 *
 * Idempotent - every statement is a grant or a revoke of a fixed set - so the
 * `migrate` command can apply them on every run rather than needing to work out
 * whether they are already in force.
 *
 * @param role - The serving role's name, as parsed from its connection URL.
 * @returns The statements, in the order they must be applied.
 * @throws {Error} When the role name is blank, which would otherwise generate a
 *   syntactically valid statement that grants to nothing.
 * @example
 * ```ts
 * for (const statement of servingRolePrivilegeStatements("signet_app")) {
 *   await db.execute(sql.raw(statement));
 * }
 * ```
 */
export function servingRolePrivilegeStatements(
  role: string,
): readonly string[] {
  if (role.trim().length === 0) {
    throw new Error(
      "A serving role name is required in order to generate its privileges",
    );
  }

  const target = quoteIdentifier(role);

  return [
    // Schema usage first: without it every grant below names something the role
    // cannot reach.
    `grant usage on schema public to ${target}`,

    // Tenant-owned and exempt tables alike. The policies decide what is visible;
    // these decide what is reachable at all.
    `grant select, insert, update, delete on all tables in schema public to ${target}`,

    // The audit trail is append-only by constitutional requirement, and this is
    // what makes the database refuse a violation rather than trusting review to
    // catch one.
    `revoke update, delete on audit_events from ${target}`,

    // So that a table created by a later migration is granted without anybody
    // remembering to. Applies to objects created by the owning identity, which
    // is the only identity that runs migrations.
    `alter default privileges in schema public grant select, insert, update, delete on tables to ${target}`,

    // The declared exemption, and nothing beyond it. `revoke ... from public` is
    // in the migration that creates each routine, so the role named here is the
    // only one that can execute them.
    ...Object.keys(PRIVILEGED_ROUTINES).map(
      (routine) => `grant execute on function ${routine} to ${target}`,
    ),
  ];
}

/**
 * Grants a serving role its access.
 *
 * Issued by the owning identity, immediately after the migrations and under the
 * same advisory lock, because the grants and the tables they name are two halves
 * of one operation. Must run after migration `0007_serving_role_privileges`,
 * which creates the routines the last statements grant `execute` on.
 *
 * Not wrapped in a transaction. `grant` and `revoke` are individually atomic, the
 * whole set is idempotent, and a partial application is repaired by the next run
 * rather than needing to be rolled back - whereas holding one transaction open
 * across a `grant ... on all tables` on a busy database is a lock nobody asked
 * for.
 *
 * @param db - A connection with authority to grant on the tables, which in
 *   practice means the identity that owns them.
 * @param role - The serving role's name, as parsed from its connection URL.
 * @throws {Error} When the role name is blank, or when a statement fails - a
 *   migration that reported success while leaving the serving role unable to
 *   reach a table would present later as an empty result.
 */
export async function applyServingRolePrivileges(
  db: Executor,
  role: string,
): Promise<void> {
  for (const statement of servingRolePrivilegeStatements(role)) {
    await db.execute(sql.raw(statement));
  }
}
