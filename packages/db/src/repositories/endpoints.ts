/**
 * Endpoint configuration.
 *
 * Reads take a {@link BoundTenantScope} and filter on `tenant_id`; writes take a
 * {@link BoundEndpointScope}, which can only have been built from an endpoint row
 * that was already proved to belong to the tenant. That asymmetry is deliberate: a
 * read has to be able to look an endpoint up by slug before a scope for it
 * exists, whereas nothing should ever update an endpoint the caller has not
 * already resolved.
 *
 * `tenantId` is absent from every input type, so no update can move an endpoint
 * between tenants. That is not an operation with a safe implementation - the
 * endpoint's clients, keys, policies and audit history would all have to move
 * with it - and making it inexpressible is cheaper than making it correct.
 *
 * Author: John Grimes
 */

import { and, eq } from "drizzle-orm";

import { requireRow } from "./rows.js";
import { executorFor } from "./scope.js";
import { nowValue } from "./time.js";
import { endpoints, idpConfigs } from "../schema/endpoints.js";

import type { BoundEndpointScope, BoundTenantScope } from "./scope.js";
import type {
  Endpoint,
  IdpConfig,
  NewEndpoint,
  NewIdpConfig,
} from "../schema/endpoints.js";

/**
 * The caller-supplied half of an endpoint.
 *
 * Every capability flag and TTL is included by construction rather than listed,
 * so a flag added to the schema is settable at creation without an edit here -
 * while `tenantId` and the generated columns stay out of reach.
 */
export type EndpointInput = Omit<
  NewEndpoint,
  "id" | "tenantId" | "createdAt" | "updatedAt"
>;

/** Creates an endpoint in the scoped tenant. */
export async function createEndpoint(
  scope: BoundTenantScope,
  input: EndpointInput,
): Promise<Endpoint> {
  const rows = await executorFor(scope)
    .insert(endpoints)
    .values({ ...input, tenantId: scope.tenantId })
    .returning();
  return requireRow(rows, "insert into endpoints");
}

/** Lists the scoped tenant's endpoints, by slug. */
export async function listEndpoints(
  scope: BoundTenantScope,
): Promise<readonly Endpoint[]> {
  return await executorFor(scope)
    .select()
    .from(endpoints)
    .where(eq(endpoints.tenantId, scope.tenantId))
    .orderBy(endpoints.slug);
}

/** Reads one of the scoped tenant's endpoints by identifier. */
export async function getEndpoint(
  scope: BoundTenantScope,
  endpointId: string,
): Promise<Endpoint | undefined> {
  const [row] = await executorFor(scope)
    .select()
    .from(endpoints)
    .where(
      and(eq(endpoints.tenantId, scope.tenantId), eq(endpoints.id, endpointId)),
    )
    .limit(1);
  return row;
}

/** Reads one of the scoped tenant's endpoints by `/e/{slug}` segment. */
export async function getEndpointBySlug(
  scope: BoundTenantScope,
  slug: string,
): Promise<Endpoint | undefined> {
  const [row] = await executorFor(scope)
    .select()
    .from(endpoints)
    .where(
      and(eq(endpoints.tenantId, scope.tenantId), eq(endpoints.slug, slug)),
    )
    .limit(1);
  return row;
}

/**
 * Reads the endpoint the scope refers to.
 *
 * The OAuth handlers already hold the row from `resolveIssuer`; this exists for
 * the paths that carry a scope across an await and need the current state of the
 * configuration rather than a snapshot of it.
 */
export async function getScopedEndpoint(
  scope: BoundEndpointScope,
): Promise<Endpoint | undefined> {
  return await getEndpoint(scope, scope.endpointId);
}

/**
 * Applies a patch to the scoped endpoint.
 *
 * The tenant predicate is applied as well as the endpoint identifier. It is
 * redundant given how an {@link EndpointScope} is built, and it stays because
 * this is the statement that would otherwise be one transposed variable away
 * from editing another tenant's configuration.
 */
export async function updateEndpoint(
  scope: BoundEndpointScope,
  patch: Partial<EndpointInput>,
  now?: Date,
): Promise<Endpoint | undefined> {
  const [row] = await executorFor(scope)
    .update(endpoints)
    .set({ ...patch, updatedAt: nowValue(now) })
    .where(
      and(
        eq(endpoints.id, scope.endpointId),
        eq(endpoints.tenantId, scope.tenantId),
      ),
    )
    .returning();
  return row;
}

/**
 * Enables or disables the scoped endpoint.
 *
 * A disabled endpoint keeps its keys, clients and tokens; it simply stops
 * serving authorization requests. Deleting it would be the destructive answer to
 * a question that is usually temporary.
 */
export async function setEndpointStatus(
  scope: BoundEndpointScope,
  status: Endpoint["status"],
  now?: Date,
): Promise<Endpoint | undefined> {
  return await updateEndpoint(scope, { status }, now);
}

/**
 * Deletes the scoped endpoint and everything configured under it.
 *
 * @returns Whether an endpoint was deleted.
 */
export async function deleteEndpoint(
  scope: BoundEndpointScope,
): Promise<boolean> {
  const rows = await executorFor(scope)
    .delete(endpoints)
    .where(
      and(
        eq(endpoints.id, scope.endpointId),
        eq(endpoints.tenantId, scope.tenantId),
      ),
    )
    .returning({ id: endpoints.id });
  return rows.length > 0;
}

/** The caller-supplied half of an upstream IdP configuration. */
export type IdpConfigInput = Omit<
  NewIdpConfig,
  "endpointId" | "createdAt" | "updatedAt"
>;

/** Reads the scoped endpoint's upstream IdP configuration. */
export async function getIdpConfig(
  scope: BoundEndpointScope,
): Promise<IdpConfig | undefined> {
  const [row] = await executorFor(scope)
    .select()
    .from(idpConfigs)
    .where(eq(idpConfigs.endpointId, scope.endpointId))
    .limit(1);
  return row;
}

/**
 * Creates or replaces the scoped endpoint's upstream IdP configuration.
 *
 * An endpoint federates to at most one provider - that is the shape of the table,
 * whose primary key is the endpoint - so this is an upsert rather than an insert
 * the caller has to know whether to make.
 */
export async function upsertIdpConfig(
  scope: BoundEndpointScope,
  input: IdpConfigInput,
  now?: Date,
): Promise<IdpConfig> {
  const rows = await executorFor(scope)
    .insert(idpConfigs)
    .values({ ...input, endpointId: scope.endpointId })
    .onConflictDoUpdate({
      target: idpConfigs.endpointId,
      set: { ...input, updatedAt: nowValue(now) },
    })
    .returning();
  return requireRow(rows, "upsert into idp_configs");
}

/**
 * Removes the scoped endpoint's upstream IdP configuration.
 *
 * @returns Whether a configuration was removed.
 */
export async function deleteIdpConfig(
  scope: BoundEndpointScope,
): Promise<boolean> {
  const rows = await executorFor(scope)
    .delete(idpConfigs)
    .where(eq(idpConfigs.endpointId, scope.endpointId))
    .returning({ endpointId: idpConfigs.endpointId });
  return rows.length > 0;
}

/** Records that the upstream discovery document was fetched. */
export async function recordIdpDiscoveryFetch(
  scope: BoundEndpointScope,
  now?: Date,
): Promise<void> {
  await executorFor(scope)
    .update(idpConfigs)
    .set({ discoveryCachedAt: nowValue(now) })
    .where(eq(idpConfigs.endpointId, scope.endpointId));
}
