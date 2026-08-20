/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Tenant and endpoint scopes - the primary defence against cross-tenant access.
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
 * conditions - that the application set a session variable, and that it
 * connected as a role which cannot bypass the policies - whereas these types
 * fail the build. RLS catches the query written outside this directory; the
 * scope types catch the query written inside it.
 *
 * An {@link EndpointScope} is a {@link TenantScope}, so a tenant-level function
 * accepts one without ceremony. It exists because most of the schema hangs off
 * `endpoints` rather than off `tenants`: verifying the endpoint's ownership once,
 * when the scope is built, lets every subsequent query filter on `endpoint_id`
 * alone instead of joining back to `tenants` on every read.
 *
 * ## Resolution, which necessarily happens unbound
 *
 * The resolvers at the foot of this module are where a scope comes into existence,
 * so they are the one thing here that cannot already have a tenant declared. Each
 * turns an identifier the request carried into a tenant `uuid` through one of the
 * routines in `./routines.ts`, then reads the rows that identifier names inside a
 * transaction declared for it. The scope they hand back is deliberately *unbound*:
 * that transaction has committed by the time they return, so a scope carrying it
 * would carry a dead handle. Callers bind it with `withTenantScope` when they come
 * to use it.
 *
 * Author: John Grimes
 */

import { and, eq, sql } from "drizzle-orm";

import { tenantIdForSlug } from "./routines.js";
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

/**
 * The transaction a scope's tenant was declared on.
 *
 * The brand and the transaction are one value deliberately: holding the brand is
 * holding the transaction in which {@link declareTenantScope} declared this
 * tenant, so there is no way to have one without the other. See
 * {@link BoundTenantScope}.
 */
const boundScopeBrand = Symbol("signet.boundScope");

/**
 * A declaration, and whether the transaction that made it is still open.
 *
 * A scope can outlive its transaction, and nothing in the type system stops it: a
 * handler resolves a client inside one transaction and then uses the scope in the
 * next, which is the ordinary shape of the OAuth code and is correct - the scope is
 * proof that a tenant was resolved, and that stays true. What is *not* true any more
 * is the declaration, and a transaction-local setting on a committed transaction is
 * not merely stale, it is absent: statements issued afterwards run on the pooled
 * connection with no tenant declared, so a read sees nothing and a write is refused.
 *
 * Silently. That is the failure this flag exists to prevent. `live` is cleared when
 * the declaring transaction ends, so {@link isBoundScope} answers false afterwards
 * and `withTenantScope` opens a fresh transaction and declares again, and
 * {@link executorFor} throws rather than issuing a statement that cannot work.
 */
interface Binding {
  readonly executor: Executor;
  /** False once the declaring transaction has committed or rolled back. */
  live: boolean;
}

/**
 * The session variable every tenant isolation policy reads.
 *
 * Declared here rather than in `../rls.ts`, which owns the policies that read it,
 * because this is the module that writes it - and a constant defined where it is
 * written keeps the dependency between the two modules pointing one way. `../rls.ts`
 * re-exports it, so the policies and their readers still name one thing.
 */
export const TENANT_SETTING = "signet.tenant_id";

/** Proof that the caller is operating within one tenant. */
export interface TenantScope {
  /** Unforgeable brand; see the module documentation. */
  readonly [tenantScopeBrand]: true;
  /**
   * The transaction this tenant was declared on, when it has been.
   *
   * Present only on a {@link BoundTenantScope}. Optional here so that the
   * narrowing functions can carry it across without a cast; it cannot be written
   * from outside this module, because the key is a private symbol.
   */
  readonly [boundScopeBrand]?: Binding;
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
 * Every runtime table - codes, tokens, consents, the `jti` ledger - hangs off a
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
 * A tenant scope whose tenant has been declared to the database.
 *
 * Carries the transaction the declaration was made on, so the established tenant
 * and the declared tenant are the same value and cannot disagree. Every data-layer
 * function that touches tenant-owned data takes one of these rather than a
 * connection and a scope: a query with no declared tenant does not compile, and
 * neither does one that declares tenant A and filters for tenant B, because there
 * is no expression naming both.
 *
 * Obtained only from {@link declareTenantScope} - in practice from
 * `withTenantScope` in `../rls.ts`, which opens the transaction it is declared on.
 */
export interface BoundTenantScope extends TenantScope {
  /** The transaction this tenant was declared on. */
  readonly [boundScopeBrand]: Binding;
}

/**
 * An endpoint scope whose tenant has been declared; see {@link BoundTenantScope}.
 *
 * An intersection rather than an interface: the brand is optional on
 * {@link TenantScope} so that the narrowing functions can carry it across without
 * a cast, and an interface cannot narrow an inherited optional member to a
 * required one.
 */
export type BoundEndpointScope = EndpointScope & BoundTenantScope;

/** A client scope whose tenant has been declared; see {@link BoundTenantScope}. */
export type BoundClientScope = ClientScope & BoundTenantScope;

/**
 * Whether a scope's tenant is declared on a transaction that is still open.
 *
 * False for a scope whose declaring transaction has ended, which is why
 * `withTenantScope` can be handed a scope resolved in an earlier transaction and
 * do the right thing with it: the declaration is gone, so it makes another.
 *
 * @param scope - Any scope.
 * @returns True when it carries a live declaration.
 * @example
 * ```ts
 * // `withTenantScope` uses this to reuse a declaration rather than repeat it.
 * if (isBoundScope(scope)) {
 *   return await work(scope);
 * }
 * ```
 */
export function isBoundScope<S extends TenantScope>(
  scope: S,
): scope is S & BoundTenantScope {
  return scope[boundScopeBrand]?.live === true;
}

/**
 * The transaction a bound scope declared its tenant on.
 *
 * Every tenant-owned read and write goes through this, which is what makes the
 * declared tenant and the queried tenant the same value rather than two values a
 * caller has to keep in step.
 *
 * @param scope - A bound scope.
 * @returns The transaction to issue tenant-owned reads and writes on.
 * @throws {Error} When that transaction has already ended. The alternative is a
 *   statement on the pooled connection with no tenant declared, which reads as an
 *   empty result rather than as the mistake it is - and a bad diagnostic is the one
 *   thing the compile-time layer exists to avoid.
 */
export function executorFor(scope: BoundTenantScope): Executor {
  const binding = scope[boundScopeBrand];
  if (!binding.live) {
    throw new Error(
      `the transaction that declared tenant ${scope.tenantId} has ended; ` +
        "re-enter withTenantScope before using this scope again",
    );
  }
  return binding.executor;
}

/**
 * Marks a declaration spent, once the transaction that made it has ended.
 *
 * Called by `withTenantScope` in `../rls.ts`, which owns the transaction and is
 * therefore the only thing that knows when it is over. Exported for that reason
 * alone.
 *
 * @param scope - The scope the declaration was made on.
 */
export function closeBinding(scope: BoundTenantScope): void {
  scope[boundScopeBrand].live = false;
}

/**
 * Copies a binding onto a narrowed scope, when the scope it narrows has one.
 *
 * Written as a copy rather than a spread of the whole source, because spreading an
 * endpoint or client scope into a narrower one would carry the source's own
 * identifiers - and a stale `clientRowId` under an intact brand is exactly the
 * mismatch the brands exist to make impossible.
 */
function carryBinding<S extends TenantScope>(
  narrowed: S,
  from: TenantScope,
): S {
  const binding = from[boundScopeBrand];
  // The same {@link Binding} object, not a copy, so that closing the declaration
  // closes it for every scope narrowed from it.
  return binding === undefined
    ? narrowed
    : { ...narrowed, [boundScopeBrand]: binding };
}

/**
 * Declares a scope's tenant on a transaction, and returns the two as one value.
 *
 * The declaration and the brand are inseparable by construction: this is the only
 * function that produces a {@link BoundTenantScope}, and it does so only after
 * issuing the `set_config` that the policies read. A scope that claims a tenant is
 * declared therefore had it declared, on the transaction it carries.
 *
 * `tx` must be a transaction. `set_config(..., true)` outside a transaction block
 * affects nothing at all, silently, so a caller handing over a pooled connection
 * would get a scope whose reads see nothing - which is fail-closed but a poor
 * diagnostic. `withTenantScope` in `../rls.ts` is the intended caller, and it opens
 * the transaction itself.
 *
 * @param tx - The transaction to declare on.
 * @param scope - The tenant, endpoint or client scope to declare.
 * @returns The same scope, bound to `tx`.
 * @example
 * ```ts
 * await db.transaction(async (tx) => {
 *   const bound = await declareTenantScope(tx, scope);
 *   return await listEndpoints(bound);
 * });
 * ```
 */
export async function declareTenantScope<S extends TenantScope>(
  tx: Executor,
  scope: S,
): Promise<S & BoundTenantScope> {
  await declareTenant(tx, scope.tenantId);
  return { ...scope, [boundScopeBrand]: { executor: tx, live: true } };
}

/**
 * Issues the statement the policies read.
 *
 * A bound parameter, not string interpolation: `SET LOCAL` does not accept
 * parameters, and building that statement by concatenation would put a value into
 * SQL text on the one code path whose whole job is to enforce a boundary.
 *
 * Separate from {@link declareTenantScope} because {@link withDeclaredTenant}
 * needs the same statement before any scope exists to declare.
 */
async function declareTenant(tx: Executor, tenantId: string): Promise<void> {
  await tx.execute(
    sql`select set_config(${TENANT_SETTING}, ${tenantId}, true)`,
  );
}

/**
 * Resolves the `/t/{slug}` segment and runs a read in a transaction declared for it.
 *
 * The three resolvers that start from a slug - a tenant scope, an issuer, and a
 * console member's tenant - share this, so the two steps are written once: the
 * routine turns the slug into a tenant identifier, and the read runs with that
 * identifier declared. A resolver that did its own preamble would be a second
 * place for the declaration to be forgotten from.
 *
 * @param db - The connection to resolve on. No tenant need be declared.
 * @param tenantSlug - The `/t/{slug}` path segment.
 * @param read - The read to perform, given the declaring transaction and the
 *   tenant identifier the slug resolved to.
 * @returns Whatever the read returns, or undefined when the slug resolves to no
 *   tenant - deliberately indistinguishable from a tenant somebody else owns.
 */
export async function withTenantForSlug<T>(
  db: Executor,
  tenantSlug: string,
  read: (tx: Executor, tenantId: string) => Promise<T | undefined>,
): Promise<T | undefined> {
  const tenantId = await tenantIdForSlug(db, tenantSlug);
  return tenantId === undefined
    ? undefined
    : await withDeclaredTenant(db, tenantId, (tx) => read(tx, tenantId));
}

/**
 * Runs a read in a transaction declared for a tenant identified by uuid alone.
 *
 * The resolvers' primitive, and the one place in this package that declares a
 * tenant without a scope to prove it was resolved - because resolving it is what
 * the caller is in the middle of doing. Each caller has just been handed a `uuid`
 * by one of the routines in `./routines.ts`, or by a session the console already
 * authenticated, and now needs to read the rows that identifier names.
 *
 * Deliberately hands over a bare {@link Executor} rather than a bound scope: the
 * scope is built *from* the rows this read returns, so it cannot exist yet. That
 * makes this the only unbound handle in the package that can reach an arbitrary
 * tenant's rows, which is why it is not for general use, is declared with a
 * justification in `./unscoped.ts`, and is called only by the resolvers.
 *
 * @param db - The connection to open a transaction on.
 * @param tenantId - The tenant to declare, from a routine or an authenticated
 *   session - never from an unauthenticated request.
 * @param read - The read to perform, given the declaring transaction.
 * @returns Whatever the read returns.
 * @example
 * ```ts
 * const tenant = await withDeclaredTenant(db, tenantId, async (tx) => {
 *   const [row] = await tx.select().from(tenants).limit(1);
 *   return row;
 * });
 * ```
 */
export async function withDeclaredTenant<T>(
  db: Executor,
  tenantId: string,
  read: (tx: Executor) => Promise<T>,
): Promise<T> {
  return await db.transaction(async (tx) => {
    await declareTenant(tx, tenantId);
    return await read(tx);
  });
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
 *
 * A bound scope narrows to a bound scope: the endpoint belongs to the tenant that
 * was declared, so the declaration still holds and there is nothing to re-declare.
 */
export function endpointScopeFromRow(
  scope: BoundTenantScope,
  endpoint: Endpoint,
): BoundEndpointScope;
export function endpointScopeFromRow(
  scope: TenantScope,
  endpoint: Endpoint,
): EndpointScope;
export function endpointScopeFromRow(
  scope: TenantScope,
  endpoint: Endpoint,
): EndpointScope {
  if (endpoint.tenantId !== scope.tenantId) {
    throw new TenantScopeViolationError(
      `endpoint ${endpoint.id} belongs to tenant ${endpoint.tenantId}, not ${scope.tenantId}`,
    );
  }

  return carryBinding(
    {
      [tenantScopeBrand]: true,
      [endpointScopeBrand]: true,
      tenantId: scope.tenantId,
      tenantSlug: scope.tenantSlug,
      endpointId: endpoint.id,
      endpointSlug: endpoint.slug,
    },
    scope,
  );
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
  scope: BoundEndpointScope,
  client: Client,
): BoundClientScope;
export function clientScopeFromRow(
  scope: EndpointScope,
  client: Client,
): ClientScope;
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

/**
 * Resolves a tenant scope from the `/t/{slug}` path segment.
 *
 * Two steps, because the slug is all the request carries and `tenants` is
 * tenant-owned: the routine turns the slug into a tenant identifier, and the row
 * is then read inside a transaction declared for that tenant. Reading the row at
 * all - rather than building the scope from the identifier and the slug already in
 * hand - is what keeps a scope from asserting the existence of a tenant that is
 * not there, and it is the read that proves the binding reaches the row.
 *
 * The scope handed back is *not* bound: the transaction has committed by the time
 * this returns, so a scope carrying it would carry a dead handle. The caller binds
 * it with `withTenantScope` when it comes to use it.
 *
 * @param db - The connection to resolve on. No tenant need be declared.
 * @param tenantSlug - The `/t/{slug}` path segment.
 * @returns The scope, or undefined for a slug that does not resolve.
 */
export async function resolveTenantScope(
  db: Executor,
  tenantSlug: string,
): Promise<TenantScope | undefined> {
  return await withTenantForSlug(db, tenantSlug, async (tx, tenantId) => {
    const [tenant] = await tx
      .select()
      .from(tenants)
      .where(eq(tenants.id, tenantId))
      .limit(1);

    return tenant === undefined ? undefined : tenantScopeFromRow(tenant);
  });
}

/**
 * Narrows a bound tenant scope to the endpoint with the given `/e/{slug}` segment.
 *
 * The tenant predicate stays in the query even though the `endpoints` policy
 * already applies it. The policy is what makes the read safe; the predicate is
 * what makes it obvious at the call site, and the two asserting the same thing is
 * the intent rather than a redundancy.
 */
export async function resolveEndpointScope(
  scope: BoundTenantScope,
  endpointSlug: string,
): Promise<BoundEndpointScope | undefined> {
  const [endpoint] = await executorFor(scope)
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

/** An issuer resolved from its URL, with the rows the OAuth handlers need. */
export interface ResolvedIssuer {
  readonly scope: EndpointScope;
  readonly tenant: Tenant;
  readonly endpoint: Endpoint;
}

/**
 * Resolves `/t/{tenantSlug}/e/{endpointSlug}`.
 *
 * Every OAuth request begins here, and every one of them needs the endpoint row
 * as well as the scope - its TTLs, capability flags and FHIR base URL. Resolving
 * the two separately would double the query count on the hottest path in the
 * server for no gain, so the join is kept and both rows come back together.
 *
 * The routine call is the one statement this gained: the tenant slug has to become
 * a tenant identifier before either row is reachable, and the join then runs inside
 * the transaction that declared it. The endpoint row is deliberately read *after*
 * binding rather than returned by a routine, because it holds a tenant's FHIR base
 * URL and capability flags - configuration an unbound caller must not be able to
 * reach.
 *
 * Both scopes handed back are unbound, for the reason
 * {@link resolveTenantScope} gives.
 *
 * @param db - The connection to resolve on. No tenant need be declared.
 * @param tenantSlug - The `/t/{slug}` path segment.
 * @param endpointSlug - The `/e/{slug}` path segment.
 * @returns The scope and both rows, or undefined when either segment does not
 *   resolve - including the case where the endpoint exists under another tenant.
 */
export async function resolveIssuer(
  db: Executor,
  tenantSlug: string,
  endpointSlug: string,
): Promise<ResolvedIssuer | undefined> {
  return await withTenantForSlug(db, tenantSlug, async (tx, tenantId) => {
    const [row] = await tx
      .select({ tenant: tenants, endpoint: endpoints })
      .from(endpoints)
      .innerJoin(tenants, eq(tenants.id, endpoints.tenantId))
      .where(and(eq(tenants.id, tenantId), eq(endpoints.slug, endpointSlug)))
      .limit(1);

    return row === undefined
      ? undefined
      : {
          scope: endpointScopeFromRow(
            tenantScopeFromRow(row.tenant),
            row.endpoint,
          ),
          tenant: row.tenant,
          endpoint: row.endpoint,
        };
  });
}

/**
 * The current transaction timestamp, read from the database rather than the
 * process clock.
 *
 * Conditional updates in this directory compare against `now()` inside SQL so
 * that there is no window between deciding an expiry and acting on it. When a
 * caller needs that same instant in TypeScript - to stamp an audit event that
 * must agree with the row it describes - it must come from the same source.
 */
export async function databaseNow(db: Executor): Promise<Date> {
  // Asked for as epoch milliseconds rather than as a timestamp. `execute` runs
  // outside Drizzle's column mapping, so a `timestamptz` arrives in its Postgres
  // text form - `2026-08-03 08:53:13.215+00`, which is not ISO 8601 and reaches
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
