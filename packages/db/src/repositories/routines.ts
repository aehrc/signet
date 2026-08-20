/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The three reads that cannot declare a tenant, because they establish one.
 *
 * Every other read and write in this package takes a `BoundTenantScope`: the
 * tenant it acts for has been declared to the database, and the transaction
 * carrying that declaration is the same value. These three cannot, because they
 * are what turns an identifier an incoming request carried into the tenant that
 * every later query is bound to - there is no tenant to declare yet.
 *
 * They therefore reach past the policies, and the shape of that exemption is the
 * point. It is not a privileged connection, which would be an exemption of
 * unlimited shape reachable from anywhere in the process; it is three
 * `security definer` routines created by migration `0007_serving_role_privileges`,
 * each taking an identifier the caller already supplied and returning identifiers
 * only. The wrappers below are the only code that calls them, so what Signet can
 * do without a tenant is three functions in one file, declared with a
 * justification each in `./unscoped.ts` and asserted against the deployed schema
 * by `../privileges.integration.test.ts`.
 *
 * None of them returns configuration. An endpoint row would put a tenant's FHIR
 * base URL, TTLs and capability flags within reach of an unbound caller, so
 * endpoint reads happen after binding, which is why each of these returns a
 * `uuid` and the caller reads the row it names inside a declared transaction.
 *
 * Author: John Grimes
 */

import { sql } from "drizzle-orm";

import type { Executor } from "./executor.js";

/** One `uuid` column, as the routines return it. */
interface TenantIdRow {
  readonly tenant_id: string | null;
}

/**
 * Reads the rows a routine returned.
 *
 * `execute` runs outside Drizzle's column mapping, so the result arrives as an
 * array-like of plain objects that TypeScript will not narrow on its own.
 */
function tenantIdsOf(result: unknown): readonly TenantIdRow[] {
  return result as readonly TenantIdRow[];
}

/**
 * Resolves the `/t/{slug}` path segment to a tenant.
 *
 * The slug is the only tenant identifier an incoming OAuth or console request
 * carries, so this necessarily precedes knowing a tenant.
 *
 * @param db - The connection to call the routine on. No tenant need be declared.
 * @param slug - The tenant's URL path segment, as supplied by the caller.
 * @returns The tenant's identifier, or undefined when the slug does not resolve -
 *   deliberately indistinguishable from a tenant belonging to somebody else, so
 *   that an unauthenticated caller cannot enumerate tenant slugs.
 * @example
 * ```ts
 * const tenantId = await tenantIdForSlug(db, "acme");
 * ```
 */
export async function tenantIdForSlug(
  db: Executor,
  slug: string,
): Promise<string | undefined> {
  const rows = tenantIdsOf(
    await db.execute(
      sql`select signet_tenant_id_for_slug(${slug}) as tenant_id`,
    ),
  );
  return rows[0]?.tenant_id ?? undefined;
}

/**
 * Resolves a personal access token's digest to the tenant that minted it.
 *
 * A personal access token is presented with no tenant in the request, and
 * `api_tokens` is tenant-owned, so the row cannot be found under the policies.
 *
 * @param db - The connection to call the routine on. No tenant need be declared.
 * @param digest - The presented token's hash, never the token itself.
 * @returns The tenant's identifier, or undefined when no token has that digest.
 * @example
 * ```ts
 * const tenantId = await tenantIdForApiTokenDigest(db, sha256(presented));
 * ```
 */
export async function tenantIdForApiTokenDigest(
  db: Executor,
  digest: string,
): Promise<string | undefined> {
  const rows = tenantIdsOf(
    await db.execute(
      sql`select signet_tenant_id_for_api_token(${digest}) as tenant_id`,
    ),
  );
  return rows[0]?.tenant_id ?? undefined;
}

/**
 * Lists the tenants a signed-in console user is a member of.
 *
 * Answering "which tenants may I see" necessarily precedes choosing one, and it
 * is the only genuinely cross-tenant read the server performs. It returns tenant
 * identifiers and nothing else: the caller reads each tenant's row inside a
 * transaction declared for that tenant.
 *
 * @param db - The connection to call the routine on. No tenant need be declared.
 * @param adminUserId - The signed-in admin user, resolved from their session.
 * @returns The identifiers of the tenants they belong to, which is empty for a
 *   user with no memberships.
 * @example
 * ```ts
 * const tenantIds = await tenantIdsForAdminUser(db, principal.adminUserId);
 * ```
 */
export async function tenantIdsForAdminUser(
  db: Executor,
  adminUserId: string,
): Promise<readonly string[]> {
  const rows = tenantIdsOf(
    await db.execute(
      sql`select signet_tenant_ids_for_admin(${adminUserId}) as tenant_id`,
    ),
  );
  return rows
    .map((row) => row.tenant_id)
    .filter((id): id is string => id !== null);
}
