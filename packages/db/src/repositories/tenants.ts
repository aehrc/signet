/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Tenant records.
 *
 * Creating a tenant is the one write in this directory that cannot take an
 * established tenant, because it is what brings one into existence. It is
 * therefore a platform operation rather than a tenant operation, and the server
 * exposes it only to the signup path and the bootstrap command - never to a
 * request already inside a tenant. It still declares a tenant before it writes:
 * it generates the identifier itself and binds to that, so the row it inserts is
 * one the policy permits and the insert is not an exception to the rule.
 *
 * Every other function here takes a bound scope and identifies the row from it,
 * so there is no signature that accepts a tenant identifier a caller could have
 * chosen: renaming or deleting some *other* tenant is not expressible.
 *
 * Author: John Grimes
 */

import { eq } from "drizzle-orm";

import { tenantIdsForAdminUser } from "./routines.js";
import { requireRow } from "./rows.js";
import { executorFor, withDeclaredTenant } from "./scope.js";
import { nowValue } from "./time.js";
import { tenantMembers, tenants } from "../schema/tenancy.js";

import type { Executor } from "./executor.js";
import type { BoundTenantScope } from "./scope.js";
import type { NewTenant, Tenant, TenantMember } from "../schema/tenancy.js";

/** The caller-supplied half of a new tenant. */
export type TenantInput = Pick<NewTenant, "slug" | "name">;

/**
 * Creates a tenant.
 *
 * The identifier is generated here rather than left to the column default,
 * because the row has to satisfy the tenant isolation policy on `tenants` -
 * `id = current_setting('signet.tenant_id')` - and there is no way to declare a
 * tenant whose identifier the database has not yet chosen. Generating it first
 * makes the one write that creates a tenant as bound as every other write.
 *
 * The slug is unique across the deployment: it is a URL path segment, so a
 * collision would make two tenants share an issuer. The unique index rejects
 * the second, and the caller should report the conflict rather than retrying.
 *
 * @param db - The connection to insert on. No tenant need be declared; this
 *   declares the one it is about to create.
 * @param input - The tenant's slug and name.
 * @returns The inserted row.
 * @throws {Error} When the slug collides, which the caller should report as a
 *   conflict - see {@link isUniqueViolation}.
 */
export async function createTenant(
  db: Executor,
  input: TenantInput,
): Promise<Tenant> {
  const id = crypto.randomUUID();
  return await withDeclaredTenant(db, id, async (tx) => {
    const rows = await tx
      .insert(tenants)
      .values({ ...input, id })
      .returning();
    return requireRow(rows, "insert into tenants");
  });
}

/** Reads the tenant the scope refers to. */
export async function getTenant(
  scope: BoundTenantScope,
): Promise<Tenant | undefined> {
  const [row] = await executorFor(scope)
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
  scope: BoundTenantScope,
  patch: Partial<TenantInput>,
  now?: Date,
): Promise<Tenant | undefined> {
  const [row] = await executorFor(scope)
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
export async function deleteTenant(scope: BoundTenantScope): Promise<boolean> {
  const rows = await executorFor(scope)
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
 *
 * The one read in the server that is genuinely cross-tenant, and therefore the one
 * that costs a statement per tenant rather than a single query. A binding names one
 * tenant, so a single query could only ever return one of them; the routine
 * answers which tenants the user belongs to, and each row is then read inside a
 * transaction declared for that tenant. The alternative - a query that saw every
 * tenant at once - is the capability this whole feature removes.
 *
 * Ordered here rather than in SQL, for the same reason: there is no single result
 * set to sort. `localeCompare` rather than a codepoint comparison, since the column
 * is a display name.
 *
 * @param db - The connection to read on. No tenant need be declared.
 * @param adminUserId - The signed-in admin user, resolved from their session.
 * @returns One entry per membership, by tenant name.
 */
export async function listTenantsForAdminUser(
  db: Executor,
  adminUserId: string,
): Promise<readonly TenantMembershipRow[]> {
  const found: TenantMembershipRow[] = [];

  for (const tenantId of await tenantIdsForAdminUser(db, adminUserId)) {
    const row = await withDeclaredTenant(db, tenantId, async (tx) => {
      const [membership] = await tx
        .select({ tenant: tenants, role: tenantMembers.role })
        .from(tenantMembers)
        .innerJoin(tenants, eq(tenants.id, tenantMembers.tenantId))
        .where(eq(tenantMembers.adminUserId, adminUserId))
        .limit(1);
      return membership;
    });

    // Absent when the tenant was deleted between the routine answering and the
    // read, which is a race rather than an error: the switcher simply does not
    // offer a tenant that has gone.
    if (row !== undefined) {
      found.push(row);
    }
  }

  return found.toSorted((left, right) =>
    left.tenant.name.localeCompare(right.tenant.name),
  );
}
