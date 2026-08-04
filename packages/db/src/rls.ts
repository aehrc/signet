/**
 * Postgres row-level security - the second of the two layers that bind Signet.
 *
 * Tenant isolation is a property of the type system first. A data-layer function
 * demands a scope - and, as this feature converts them, a scope bound to the
 * transaction that declared its tenant - none of which can be written down by
 * hand, so a query that has not proved which tenant it belongs to does not
 * compile. That layer is first because it fails at build time, in every
 * environment, whether or not anybody remembered to configure anything, and
 * because a compiler naming a file and a line is a better diagnostic than a query
 * that quietly returns nothing.
 *
 * The policies below are what make the database refuse the same query rather than
 * trust that the types prevented it from being written. They bind every connection
 * whose role is not exempt - a `psql` session, a reporting job, an analytics tool,
 * a service added later, none of which passes through the compiler at all - and
 * Signet's own, which is the change this feature is making.
 *
 * That requires Signet to connect as a role that owns none of these tables, since
 * Postgres exempts a table's owner from its policies. The owning identity is used
 * only where it is unavoidable: `migrate`, which is DDL, and the cross-tenant
 * expiry sweep. `./enforcement.ts` refuses to start a server whose role turns out
 * to be exempt after all, because that is a configuration mistake no code review
 * could catch.
 *
 * Three reads cannot declare a tenant, because they are what establishes one:
 * resolving `/t/{slug}`, resolving a personal access token's digest, and answering
 * which tenants a signed-in console user may see. They reach past the policies
 * through the `security definer` routines declared in `./privileges.ts`, so the
 * process holds no handle that can read an arbitrary tenant.
 *
 * What is *not* yet true at this commit is that every tenant-owned read and write
 * declares its tenant: the data layer still takes an unbound executor in the
 * modules listed in `./repositories/unscoped.ts`, and the suite still connects as
 * the owning identity. Converting them is the next step, and this paragraph goes
 * with it.
 *
 * Neither layer substitutes for the other, and neither may be dropped because the
 * other exists. See the second principle in `CLAUDE.md`.
 *
 * ## The `signet.tenant_id` convention
 *
 * Every policy compares against `current_setting('signet.tenant_id', true)`. The
 * `true` makes a missing setting return NULL rather than raise, and a NULL
 * comparison yields NULL, which is not true - so a connection that has *not* set
 * the variable sees no tenant-owned rows at all. Fail-closed: forgetting the
 * setting produces an obviously empty result, never a quietly cross-tenant one.
 *
 * {@link withTenantScope} is what sets it, and
 * `declareTenantScope` in `./repositories/scope.ts` issues the statement. The two
 * are one mechanism: the value that proves a tenant was resolved is the same value
 * that carries the transaction the tenant was declared on, so the established
 * tenant and the declared tenant cannot disagree.
 *
 * The value is bound as a parameter to `set_config`, not interpolated into a
 * `SET LOCAL` statement, because `SET LOCAL` does not accept parameters and
 * building that statement by string concatenation would put a value into SQL text
 * on the one code path whose entire job is to enforce a boundary.
 *
 * `set_config(..., true)` is transaction-local, so the setting is released when the
 * transaction ends and cannot leak to the next request that borrows the pooled
 * connection. That is why {@link withTenantScope} opens a transaction rather than
 * setting the variable on the connection: `SET LOCAL` outside a transaction block
 * affects nothing at all, silently.
 *
 * ## Deployment
 *
 * The policies are installed by migration `0006_tenant_row_level_security`, which
 * is generated from this file, so running `migrate` is all a deployment does to
 * get them. `rls.migration.test.ts` asserts they are actually in the migration
 * folder rather than merely generatable, which is the failure this file once had.
 * `rls.enforcement.integration.test.ts` then asserts they bite for the serving
 * role, per covered table, unbound and bound.
 *
 * `force: true` additionally subjects the owner to the policies. It stays off:
 * forcing would subject the owning identity to them too, which breaks the
 * cross-tenant sweep and the migrations themselves, and it buys nothing once the
 * serving role is non-owning and the startup check refuses an exempt one. It is
 * offered for a deployment that wants it and is prepared to arrange those roles.
 *
 * Author: John Grimes
 */

import { sql } from "drizzle-orm";

import {
  closeBinding,
  declareTenantScope,
  isBoundScope,
  TENANT_SETTING,
} from "./repositories/scope.js";

import type { Executor } from "./repositories/executor.js";
import type { BoundTenantScope, TenantScope } from "./repositories/scope.js";

/**
 * The session variable every policy reads.
 *
 * Defined in `./repositories/scope.js`, which is the module that writes it, and
 * re-exported here because the policies below are what read it.
 */
export { TENANT_SETTING } from "./repositories/scope.js";

/** The name every policy is created under, so it can be replaced idempotently. */
export const TENANT_POLICY_NAME = "signet_tenant_isolation";

/**
 * The current tenant, as SQL.
 *
 * `nullif(..., '')` guards the one input that would raise instead of yielding
 * NULL: an empty string is not a valid uuid, and `''::uuid` is an error rather
 * than a false predicate. A caller who set the variable to an empty string should
 * see no rows, not a failed query.
 */
const CURRENT_TENANT = `nullif(current_setting('${TENANT_SETTING}', true), '')::uuid`;

/**
 * How each tenant-scoped table reaches its tenant.
 *
 * Written out per table rather than generated, because the join path is the
 * security property: `authorization_codes` reaching its tenant through the wrong
 * table would be a policy that permits everything, and it would look just as
 * plausible as this one.
 *
 * The nested lookups compose safely. RLS applies inside a policy's own subqueries,
 * so the `EXISTS` on `endpoints` is itself filtered by the `endpoints` policy -
 * which asserts the same tenant, so the result is the same predicate twice, not a
 * loophole.
 */
const TENANT_PREDICATES: Readonly<Record<string, string>> = {
  // Direct: the row names its tenant.
  tenants: `id = ${CURRENT_TENANT}`,
  tenant_members: `tenant_id = ${CURRENT_TENANT}`,
  api_tokens: `tenant_id = ${CURRENT_TENANT}`,
  audit_events: `tenant_id = ${CURRENT_TENANT}`,
  endpoints: `tenant_id = ${CURRENT_TENANT}`,

  // One hop: through the endpoint the row is configured on.
  endpoint_keys: viaEndpoint("endpoint_keys"),
  idp_configs: viaEndpoint("idp_configs"),
  end_users: viaEndpoint("end_users"),
  clients: viaEndpoint("clients"),
  client_requests: viaEndpoint("client_requests"),
  policies: viaEndpoint("policies"),
  launch_contexts: viaEndpoint("launch_contexts"),
  authorization_sessions: viaEndpoint("authorization_sessions"),
  access_tokens: viaEndpoint("access_tokens"),
  refresh_tokens: viaEndpoint("refresh_tokens"),
  consents: viaEndpoint("consents"),
  end_user_sessions: viaEndpoint("end_user_sessions"),
  federation_states: viaEndpoint("federation_states"),

  // Two hops: through the client, which is on an endpoint.
  client_policy_overrides: viaClient("client_policy_overrides", "client_id"),
  jti_replay: viaClient("jti_replay", "client_id"),

  // Two hops: through the session the code was issued against.
  authorization_codes: `exists (
    select 1
    from authorization_sessions s
    join endpoints e on e.id = s.endpoint_id
    where s.id = authorization_codes.session_id
      and e.tenant_id = ${CURRENT_TENANT}
  )`,
};

/**
 * Tables that carry no tenant, with the reason each is exempt.
 *
 * Present so that the accompanying test can assert every table in the schema is
 * either covered by a policy or listed here. A new tenant-owned table added
 * without a policy then fails a test rather than shipping unprotected - which is
 * the failure mode this whole file exists to catch, so it must not be possible to
 * introduce it silently.
 */
export const RLS_EXEMPT_TABLES: Readonly<Record<string, string>> = {
  admin_users:
    "A person, not a tenant's property. One human may belong to several tenants and must hold one password, so the identity cannot be scoped to any of them.",
  admin_sessions:
    "Belongs to an admin user rather than to a tenant, and is resolved before any tenant is known - the session is what determines which tenants the caller may see.",
};

/** `EXISTS` through the row's own `endpoint_id`. */
function viaEndpoint(table: string): string {
  return `exists (
    select 1 from endpoints e
    where e.id = ${table}.endpoint_id
      and e.tenant_id = ${CURRENT_TENANT}
  )`;
}

/** `EXISTS` through the row's client, and that client's endpoint. */
function viaClient(table: string, column: string): string {
  return `exists (
    select 1
    from clients c
    join endpoints e on e.id = c.endpoint_id
    where c.id = ${table}.${column}
      and e.tenant_id = ${CURRENT_TENANT}
  )`;
}

/** Every table a tenant isolation policy is created on. */
export const RLS_TABLES: readonly string[] = Object.keys(TENANT_PREDICATES);

/** How the policies should be installed. */
export interface RowLevelSecurityOptions {
  /**
   * Also subject the table owner to the policies.
   *
   * Stricter, and it means migrations and the expiry sweep must connect as a role
   * holding `BYPASSRLS`. Off by default so that installing RLS cannot break the
   * migration that installs it.
   */
  readonly force?: boolean;
}

/**
 * The statements that install tenant isolation.
 *
 * Idempotent: each policy is dropped if it exists before being created, so the
 * script can be re-run after a table is added without a bespoke migration. Returned
 * as strings rather than executed so that they can be reviewed, written into a
 * migration, or diffed in a test - an isolation policy nobody can read is not
 * worth much.
 *
 * `FOR ALL USING (...)` covers reads and writes both: Postgres applies a
 * `FOR ALL` policy's `USING` expression as the `WITH CHECK` expression when none is
 * given, so a row cannot be inserted into another tenant either. Stating it once
 * removes the possibility of the two drifting apart.
 */
export function rowLevelSecurityStatements(
  options: RowLevelSecurityOptions = {},
): readonly string[] {
  const statements: string[] = [];

  for (const table of RLS_TABLES) {
    const predicate = TENANT_PREDICATES[table];
    if (predicate === undefined) {
      continue;
    }

    statements.push(`alter table ${table} enable row level security`);
    if (options.force === true) {
      statements.push(`alter table ${table} force row level security`);
    }
    statements.push(
      `drop policy if exists ${TENANT_POLICY_NAME} on ${table}`,
      `create policy ${TENANT_POLICY_NAME} on ${table} for all using (${predicate})`,
    );
  }

  return statements;
}

/** The statements as one script, for review or for a migration file. */
export function rowLevelSecurityScript(
  options: RowLevelSecurityOptions = {},
): string {
  return `${rowLevelSecurityStatements(options)
    .map((statement) => `${statement};`)
    .join("\n")}\n`;
}

/**
 * Installs tenant isolation.
 *
 * Must be run by the table owner. Every statement is DDL and therefore
 * transactional in Postgres, so the whole thing applies or none of it does - a
 * half-installed set of policies would protect some tables and not others, which is
 * worse than none, because it would look done.
 */
export async function applyRowLevelSecurity(
  db: Executor,
  options: RowLevelSecurityOptions = {},
): Promise<void> {
  await db.transaction(async (tx) => {
    for (const statement of rowLevelSecurityStatements(options)) {
      await tx.execute(sql.raw(statement));
    }
  });
}

/**
 * Runs work in a transaction that has declared the scope's tenant.
 *
 * The scope is the proof that a tenant was resolved; this makes the database agree
 * with it, and hands the work back a scope that carries both facts as one value:
 *
 * ```ts
 * const endpoints = await withTenantScope(db, scope, (bound) =>
 *   listEndpoints(bound),
 * );
 * ```
 *
 * Handed a scope that is already bound, it reuses the declaration: the work runs on
 * the transaction already open, with no second `set_config` and no nested
 * transaction. That is what makes a data-layer function safe to call from another
 * one, and it is why the binding is carried by the scope rather than inferred from
 * "a transaction is open" - a transaction bound to another tenant is exactly the
 * bug this exists to prevent, so it cannot be a safe thing to reuse blindly.
 *
 * Handed a scope whose declaring transaction has *ended*, it declares again. That is
 * the common case rather than an edge: a scope resolved inside one transaction is a
 * value handlers keep and use in the next, and the proof it carries - that this
 * tenant was resolved - outlives the declaration that was made from it.
 *
 * The declaration is transaction-local, so it is gone when this returns and cannot
 * follow the pooled connection into the next request.
 *
 * @param db - The connection to open a transaction on. Not consulted when `scope`
 *   is already bound, since the transaction it carries is the one to use.
 * @param scope - The tenant, endpoint or client scope the work acts for.
 * @param work - What to run, given the scope bound to the declaring transaction.
 * @returns Whatever the work returns.
 */
export async function withTenantScope<S extends TenantScope, T>(
  db: Executor,
  scope: S,
  work: (bound: S & BoundTenantScope) => Promise<T>,
): Promise<T> {
  if (isBoundScope(scope)) {
    // Already declared, so `db` is not consulted: opening a second transaction
    // here would give the inner work its own atomicity boundary, and declaring a
    // second time would be a statement that changes nothing.
    return await work(scope);
  }

  return await db.transaction(async (tx) => {
    const bound = await declareTenantScope(tx, scope);
    try {
      return await work(bound);
    } finally {
      // The declaration dies with the transaction, so the scope must stop claiming
      // to carry one. A handler that resolved a client here and uses it in the next
      // transaction is the ordinary shape of the OAuth code, and this is what makes
      // that safe: the next call sees an unbound scope and declares again, rather
      // than issuing statements against a transaction that has committed.
      closeBinding(bound);
    }
  });
}

/**
 * The tenant the current transaction is scoped to, as the database sees it.
 *
 * For diagnostics and for the integration tests that prove the policies work at
 * all. Returns null when no scope has been set, which is the state in which a
 * policy-bound connection sees nothing.
 */
export async function currentTenantSetting(
  db: Executor,
): Promise<string | null> {
  const rows = await db.execute<{ tenant: string | null }>(
    sql`select nullif(current_setting(${TENANT_SETTING}, true), '') as tenant`,
  );
  const first = (rows as unknown as readonly { tenant: string | null }[])[0];
  return first?.tenant ?? null;
}
