/**
 * Tenant and endpoint scopes — the primary defence against cross-tenant access.
 *
 * Tenant isolation in Signet is a property of the type system, not of code
 * review. Every repository function that touches tenant-owned data requires a
 * {@link TenantScope} or an {@link EndpointScope}, and neither can be written
 * down: both carry a module-private brand, so the only ways to obtain one are to
 * resolve it against the database or to hand over a row that could only have
 * come from the database. `listEndpoints()` cannot be called without first
 * having proved which tenant the caller is in, because there is no expression of
 * type `TenantScope` available to a caller that has not.
 *
 * Postgres row-level security (`../rls.ts`) enforces the same property inside
 * the database, and is deliberately second. RLS depends on two runtime
 * conditions — that the application set a session variable, and that it
 * connected as a role which cannot bypass the policies — whereas these types
 * fail the build. RLS catches the query written outside this directory; the
 * scope types catch the query written inside it.
 *
 * An {@link EndpointScope} is a {@link TenantScope}, so a tenant-level function
 * accepts one without ceremony. It exists because most of the schema hangs off
 * `endpoints` rather than off `tenants`: verifying the endpoint's ownership once,
 * when the scope is built, lets every subsequent query filter on `endpoint_id`
 * alone instead of joining back to `tenants` on every read.
 */

import { and, eq, sql } from "drizzle-orm";

import { clients } from "../schema/clients.js";
import { endpoints } from "../schema/endpoints.js";
import { tenants } from "../schema/tenancy.js";

import type { Executor } from "./executor.js";
import type { Client } from "../schema/clients.js";
import type { Endpoint } from "../schema/endpoints.js";
import type { Tenant } from "../schema/tenancy.js";

// Real symbols rather than `declare const ... : unique symbol`, so that the
// branded objects can be built without a cast. Not exported, which is what makes
// the brand unforgeable from outside this module.
const tenantScopeBrand = Symbol("signet.tenantScope");
const endpointScopeBrand = Symbol("signet.endpointScope");
const clientScopeBrand = Symbol("signet.clientScope");

/** Proof that the caller is operating within one tenant. */
export interface TenantScope {
  /** Unforgeable brand; see the module documentation. */
  readonly [tenantScopeBrand]: true;
  readonly tenantId: string;
  /** The tenant's URL path segment, as in `/t/{slug}`. */
  readonly tenantSlug: string;
}

/** Proof that the caller is operating within one endpoint of one tenant. */
export interface EndpointScope extends TenantScope {
  /** Unforgeable brand; see the module documentation. */
  readonly [endpointScopeBrand]: true;
  readonly endpointId: string;
  /** The endpoint's URL path segment, as in `/e/{slug}`. */
  readonly endpointSlug: string;
}

/**
 * Proof that the caller is operating on one client of one endpoint.
 *
 * Every runtime table — codes, tokens, consents, the `jti` ledger — hangs off a
 * client, and the writes into them happen deep inside a grant handler where the
 * endpoint is several frames away. Requiring this scope means an access token
 * cannot be recorded against a client that belongs to a different endpoint, and
 * a `jti` cannot be booked against a client the caller never resolved: the
 * identifiers travel together with the proof that they belong together.
 *
 * Both identifiers are carried because both are needed. `clientRowId` is the
 * surrogate key the runtime tables reference; `clientId` is the OAuth identifier
 * that appears in tokens and introspection responses.
 */
export interface ClientScope extends EndpointScope {
  /** Unforgeable brand; see the module documentation. */
  readonly [clientScopeBrand]: true;
  /** Surrogate `clients.id`, which every runtime table references. */
  readonly clientRowId: string;
  /** The OAuth `client_id`, as it appears in an issued token. */
  readonly clientId: string;
}

/**
 * Thrown when a row is offered to a scope constructor that does not own it.
 *
 * This is a programming error rather than a user-facing condition: it means two
 * verified values were combined that do not belong together, which no request
 * path should be able to produce.
 */
export class TenantScopeViolationError extends Error {
  /** @param message - What was combined with what. */
  public constructor(message: string) {
    super(message);
    this.name = "TenantScopeViolationError";
  }
}

/**
 * Builds a tenant scope from a tenant row.
 *
 * Requiring a whole {@link Tenant} is the point: a caller that has one has
 * already read the tenant from the database, so the scope cannot assert the
 * existence of a tenant that is not there.
 */
export function tenantScopeFromRow(tenant: Tenant): TenantScope {
  return {
    [tenantScopeBrand]: true,
    tenantId: tenant.id,
    tenantSlug: tenant.slug,
  };
}

/**
 * Narrows a tenant scope to one of its endpoints.
 *
 * Throws {@link TenantScopeViolationError} when the endpoint belongs to a
 * different tenant. That check is what makes every later `endpoint_id`-only
 * predicate sound.
 */
export function endpointScopeFromRow(
  scope: TenantScope,
  endpoint: Endpoint,
): EndpointScope {
  if (endpoint.tenantId !== scope.tenantId) {
    throw new TenantScopeViolationError(
      `endpoint ${endpoint.id} belongs to tenant ${endpoint.tenantId}, not ${scope.tenantId}`,
    );
  }

  return {
    [tenantScopeBrand]: true,
    [endpointScopeBrand]: true,
    tenantId: scope.tenantId,
    tenantSlug: scope.tenantSlug,
    endpointId: endpoint.id,
    endpointSlug: endpoint.slug,
  };
}

/**
 * Narrows an endpoint scope to one of its clients.
 *
 * Throws {@link TenantScopeViolationError} when the client belongs to a
 * different endpoint. Since `clients.client_id` is globally unique, a caller
 * that looked one up without an endpoint predicate could otherwise hold a client
 * from another tenant entirely; this is where that is caught.
 */
export function clientScopeFromRow(
  scope: EndpointScope,
  client: Client,
): ClientScope {
  if (client.endpointId !== scope.endpointId) {
    throw new TenantScopeViolationError(
      `client ${client.id} belongs to endpoint ${client.endpointId}, not ${scope.endpointId}`,
    );
  }

  return {
    ...scope,
    [clientScopeBrand]: true,
    clientRowId: client.id,
    clientId: client.clientId,
  };
}

/** Resolves a tenant scope from the `/t/{slug}` path segment. */
export async function resolveTenantScope(
  db: Executor,
  tenantSlug: string,
): Promise<TenantScope | undefined> {
  const [tenant] = await db
    .select()
    .from(tenants)
    .where(eq(tenants.slug, tenantSlug))
    .limit(1);

  return tenant === undefined ? undefined : tenantScopeFromRow(tenant);
}

/** Resolves a tenant scope from a tenant identifier. */
export async function resolveTenantScopeById(
  db: Executor,
  tenantId: string,
): Promise<TenantScope | undefined> {
  const [tenant] = await db
    .select()
    .from(tenants)
    .where(eq(tenants.id, tenantId))
    .limit(1);

  return tenant === undefined ? undefined : tenantScopeFromRow(tenant);
}

/** Narrows a tenant scope to the endpoint with the given `/e/{slug}` segment. */
export async function resolveEndpointScope(
  db: Executor,
  scope: TenantScope,
  endpointSlug: string,
): Promise<EndpointScope | undefined> {
  const [endpoint] = await db
    .select()
    .from(endpoints)
    .where(
      and(
        eq(endpoints.tenantId, scope.tenantId),
        eq(endpoints.slug, endpointSlug),
      ),
    )
    .limit(1);

  return endpoint === undefined
    ? undefined
    : endpointScopeFromRow(scope, endpoint);
}

/** A client resolved by its OAuth identifier, with its scope. */
export interface ResolvedClient {
  readonly scope: ClientScope;
  readonly client: Client;
}

/**
 * Resolves the `client_id` presented at `/authorize` or `/token`.
 *
 * The endpoint predicate is applied in SQL as well as being re-checked by
 * {@link clientScopeFromRow}: a client identifier registered on another
 * endpoint must read as unknown here, not as a client that then fails a later
 * check — the two are different error responses and different audit events.
 *
 * The client's status is deliberately not filtered. A suspended client
 * presenting a valid secret must be told it is suspended, and that decision is
 * the grant handler's to make and audit.
 */
export async function resolveClientScope(
  db: Executor,
  scope: EndpointScope,
  clientId: string,
): Promise<ResolvedClient | undefined> {
  const [client] = await db
    .select()
    .from(clients)
    .where(
      and(
        eq(clients.endpointId, scope.endpointId),
        eq(clients.clientId, clientId),
      ),
    )
    .limit(1);

  return client === undefined
    ? undefined
    : { scope: clientScopeFromRow(scope, client), client };
}

/** An issuer resolved from its URL, with the rows the OAuth handlers need. */
export interface ResolvedIssuer {
  readonly scope: EndpointScope;
  readonly tenant: Tenant;
  readonly endpoint: Endpoint;
}

/**
 * Resolves `/t/{tenantSlug}/e/{endpointSlug}` in a single round trip.
 *
 * Every OAuth request begins here, and every one of them needs the endpoint row
 * as well as the scope — its TTLs, capability flags and FHIR base URL. Resolving
 * the two separately would double the query count on the hottest path in the
 * server for no gain.
 */
export async function resolveIssuer(
  db: Executor,
  tenantSlug: string,
  endpointSlug: string,
): Promise<ResolvedIssuer | undefined> {
  const [row] = await db
    .select({ tenant: tenants, endpoint: endpoints })
    .from(endpoints)
    .innerJoin(tenants, eq(tenants.id, endpoints.tenantId))
    .where(and(eq(tenants.slug, tenantSlug), eq(endpoints.slug, endpointSlug)))
    .limit(1);

  if (row === undefined) {
    return undefined;
  }

  const scope = endpointScopeFromRow(
    tenantScopeFromRow(row.tenant),
    row.endpoint,
  );
  return { scope, tenant: row.tenant, endpoint: row.endpoint };
}

/**
 * The current transaction timestamp, read from the database rather than the
 * process clock.
 *
 * Conditional updates in this directory compare against `now()` inside SQL so
 * that there is no window between deciding an expiry and acting on it. When a
 * caller needs that same instant in TypeScript — to stamp an audit event that
 * must agree with the row it describes — it must come from the same source.
 */
export async function databaseNow(db: Executor): Promise<Date> {
  // Asked for as epoch milliseconds rather than as a timestamp. `execute` runs
  // outside Drizzle's column mapping, so a `timestamptz` arrives in its Postgres
  // text form — `2026-08-03 08:53:13.215+00`, which is not ISO 8601 and reaches
  // JavaScript as a string that only a lenient date parser will accept. An integer
  // has one spelling and no locale.
  const rows = await db.execute<{ epoch_ms: unknown }>(
    sql`select (extract(epoch from now()) * 1000)::bigint as epoch_ms`,
  );
  const first = (rows as unknown as readonly { epoch_ms: unknown }[])[0];
  if (first === undefined) {
    throw new Error("select now() returned no rows");
  }

  const milliseconds = Number(first.epoch_ms);
  if (!Number.isFinite(milliseconds)) {
    throw new TypeError(
      `could not read the database clock: ${String(first.epoch_ms)}`,
    );
  }
  return new Date(milliseconds);
}
