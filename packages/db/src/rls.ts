/**
 * Postgres row-level security — the backstop, not the defence.
 *
 * Tenant isolation in Signet is primarily a property of the type system. Every
 * repository function demands a `TenantScope`, `EndpointScope` or `ClientScope`,
 * none of which can be written down by hand, so a query that has not proved which
 * tenant it belongs to does not compile. That is the defence, and it is first
 * because it fails at build time, in every environment, whether or not anybody
 * remembered to configure anything.
 *
 * Row-level security exists for what that cannot cover: a hand-written `sql` query
 * somewhere outside `./repositories/`, a migration script, an ad-hoc join added in
 * a hurry, or a future contributor who reaches for the Drizzle handle directly.
 * The policies below make the database refuse to return another tenant's rows even
 * when the application forgets to ask it not to.
 *
 * It is second, rather than first, because it depends on two runtime conditions
 * that the type system does not: that the connection ran
 * `SET LOCAL signet.tenant_id`, and that it did not connect as a role which
 * bypasses policies. Both are easy to get right and neither is checked by the
 * compiler.
 *
 * ## The `signet.tenant_id` convention
 *
 * Every policy compares against `current_setting('signet.tenant_id', true)`. The
 * `true` makes a missing setting return NULL rather than raise, and a NULL
 * comparison yields NULL, which is not true — so a connection that has *not* set
 * the variable sees no tenant-owned rows at all. Fail-closed: forgetting the
 * setting produces an obviously empty result, never a quietly cross-tenant one.
 *
 * {@link withTenantScope} is the only thing that should set it. The value is bound
 * as a parameter to `set_config`, not interpolated into a `SET LOCAL` statement,
 * because `SET LOCAL` does not accept parameters and building that statement by
 * string concatenation would put a value into SQL text on the one code path whose
 * entire job is to enforce a boundary.
 *
 * `set_config(..., true)` is transaction-local, so the setting is released when the
 * transaction ends and cannot leak to the next request that borrows the pooled
 * connection. That is why this function opens a transaction rather than setting the
 * variable on the connection: `SET LOCAL` outside a transaction block affects
 * nothing at all, silently.
 *
 * ## Deployment
 *
 * `ENABLE ROW LEVEL SECURITY` does not apply to a table's owner. That is
 * deliberate on Postgres's part and useful here: migrations and the expiry sweep
 * are cross-tenant by design and connect as the owner, while the application should
 * connect as a separate, non-owning role — conventionally `signet_app` — for which
 * the policies bite. Passing `force: true` additionally subjects the owner to them,
 * which is the stricter posture and requires the sweep to run as a role with
 * `BYPASSRLS`.
 */

import { sql } from "drizzle-orm";

import type { Executor } from "./repositories/executor.js";
import type { TenantScope } from "./repositories/scope.js";

/** The session variable every policy reads. */
export const TENANT_SETTING = "signet.tenant_id";

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
 * so the `EXISTS` on `endpoints` is itself filtered by the `endpoints` policy —
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
 * without a policy then fails a test rather than shipping unprotected — which is
 * the failure mode this whole file exists to catch, so it must not be possible to
 * introduce it silently.
 */
export const RLS_EXEMPT_TABLES: Readonly<Record<string, string>> = {
  admin_users:
    "A person, not a tenant's property. One human may belong to several tenants and must hold one password, so the identity cannot be scoped to any of them.",
  admin_sessions:
    "Belongs to an admin user rather than to a tenant, and is resolved before any tenant is known — the session is what determines which tenants the caller may see.",
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
 * migration, or diffed in a test — an isolation policy nobody can read is not
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
 * transactional in Postgres, so the whole thing applies or none of it does — a
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
 * Runs work in a transaction that the tenant policies will accept.
 *
 * The scope is the proof that a tenant was resolved; this makes the database agree
 * with it. Use it to wrap a request's data access when the application connects as
 * a role that policies apply to:
 *
 * ```ts
 * const endpoints = await withTenantScope(db, scope, (tx) =>
 *   listEndpoints(tx, scope),
 * );
 * ```
 *
 * The setting is transaction-local, so it is gone when this returns and cannot
 * follow the pooled connection into the next request.
 */
export async function withTenantScope<T>(
  db: Executor,
  scope: TenantScope,
  work: (tx: Executor) => Promise<T>,
): Promise<T> {
  return await db.transaction(async (tx) => {
    // A bound parameter, not string interpolation; see the module header.
    await tx.execute(
      sql`select set_config(${TENANT_SETTING}, ${scope.tenantId}, true)`,
    );
    return await work(tx);
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
