/**
 * Tenant records.
 *
 * Creating a tenant is the one operation in this directory that cannot take a
 * {@link TenantScope}, because it is what brings a tenant into existence. It is
 * therefore a platform operation rather than a tenant operation, and the server
 * exposes it only to the signup path and the bootstrap command - never to a
 * request already inside a tenant.
 *
 * Every other function here takes a scope and identifies the row from it, so
 * there is no signature that accepts a tenant identifier a caller could have
 * chosen: renaming or deleting some *other* tenant is not expressible.
 *
 * Author: John Grimes
 */

import { eq } from "drizzle-orm";

import { requireRow } from "./rows.js";
import { nowValue } from "./time.js";
import { tenantMembers, tenants } from "../schema/tenancy.js";

import type { Executor } from "./executor.js";
import type { TenantScope } from "./scope.js";
import type { NewTenant, Tenant, TenantMember } from "../schema/tenancy.js";

/** The caller-supplied half of a new tenant. */
export type TenantInput = Pick<NewTenant, "slug" | "name">;

/**
 * Creates a tenant.
 *
 * The slug is unique across the deployment: it is a URL path segment, so a
 * collision would make two tenants share an issuer. The unique index rejects
 * the second, and the caller should report the conflict rather than retrying.
 */
export async function createTenant(
  db: Executor,
  input: TenantInput,
): Promise<Tenant> {
  const rows = await db.insert(tenants).values(input).returning();
  return requireRow(rows, "insert into tenants");
}

/** Reads the tenant the scope refers to. */
export async function getTenant(
  db: Executor,
  scope: TenantScope,
): Promise<Tenant | undefined> {
  const [row] = await db
    .select()
    .from(tenants)
    .where(eq(tenants.id, scope.tenantId))
    .limit(1);
  return row;
}

/**
 * Renames the scoped tenant, or changes its slug.
 *
 * Changing the slug changes every endpoint issuer under the tenant, which
 * invalidates already-issued tokens' `iss` and every app's configuration. The
 * console warns; the repository allows it, because a tenant that mistyped its
 * own name on day one should not be stuck with it forever.
 */
export async function updateTenant(
  db: Executor,
  scope: TenantScope,
  patch: Partial<TenantInput>,
  now?: Date,
): Promise<Tenant | undefined> {
  const [row] = await db
    .update(tenants)
    .set({ ...patch, updatedAt: nowValue(now) })
    .where(eq(tenants.id, scope.tenantId))
    .returning();
  return row;
}

/**
 * Deletes the scoped tenant and everything under it.
 *
 * Every tenant-owned table cascades from here, audit events included. That is
 * intentional and is the only path by which an audit event is ever removed:
 * deleting a tenant is a full erasure, not a soft delete.
 *
 * @returns Whether a tenant was deleted.
 */
export async function deleteTenant(
  db: Executor,
  scope: TenantScope,
): Promise<boolean> {
  const rows = await db
    .delete(tenants)
    .where(eq(tenants.id, scope.tenantId))
    .returning({ id: tenants.id });
  return rows.length > 0;
}

/** A tenant an admin user belongs to, and the authority they hold in it. */
export interface TenantMembershipRow {
  readonly tenant: Tenant;
  readonly role: TenantMember["role"];
}

/**
 * Lists the tenants an admin user may see.
 *
 * This is the console's tenant switcher, and it is intentionally driven by
 * `tenant_members` rather than by any notion of ownership: membership is the only
 * thing that grants visibility, so a tenant with no membership row for this user
 * cannot appear even if the user created it.
 */
export async function listTenantsForAdminUser(
  db: Executor,
  adminUserId: string,
): Promise<readonly TenantMembershipRow[]> {
  const rows = await db
    .select({ tenant: tenants, role: tenantMembers.role })
    .from(tenantMembers)
    .innerJoin(tenants, eq(tenants.id, tenantMembers.tenantId))
    .where(eq(tenantMembers.adminUserId, adminUserId))
    .orderBy(tenants.name);

  return rows;
}
