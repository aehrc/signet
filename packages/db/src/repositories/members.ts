/**
 * Tenant membership - where a console request acquires its tenant scope.
 *
 * {@link resolveTenantScopeForMember} is the only way a browser request obtains a
 * {@link TenantScope}, and it will not produce one without a membership row. That
 * is the whole authorisation check for the console, expressed as a join: an admin
 * user who is not a member of the tenant named in the URL gets `undefined`, and
 * with no scope in hand there is no repository function they can call. The
 * generic `resolveTenantScope` in `./scope.js` exists for the OAuth endpoints,
 * which are authenticated by client credentials rather than by membership; the
 * admin API must use this one instead.
 *
 * Author: John Grimes
 */

import { and, eq } from "drizzle-orm";

import { wouldRemoveLastOwner } from "./roles.js";
import { requireRow } from "./rows.js";
import { tenantScopeFromRow } from "./scope.js";
import { adminUsers, tenantMembers, tenants } from "../schema/tenancy.js";

import type { Executor } from "./executor.js";
import type { MembershipSummary, TenantRole } from "./roles.js";
import type { TenantScope } from "./scope.js";
import type { AdminUser, TenantMember } from "../schema/tenancy.js";
import type { SQL } from "drizzle-orm";

/** A tenant scope together with the authority the caller holds in it. */
export interface MemberTenantScope {
  readonly scope: TenantScope;
  readonly role: TenantRole;
}

/**
 * The one query that both public resolvers use.
 *
 * The join to `tenant_members` is the authorisation check, so it is written once:
 * a second copy differing by which column identifies the tenant would be a second
 * place for the membership predicate to be dropped from.
 *
 * @param db - The connection or transaction to use.
 * @param tenantPredicate - Identifies the tenant, by slug or by identifier.
 * @param adminUserId - The signed-in admin user.
 */
async function resolveMembership(
  db: Executor,
  tenantPredicate: SQL,
  adminUserId: string,
): Promise<MemberTenantScope | undefined> {
  const [row] = await db
    .select({ tenant: tenants, role: tenantMembers.role })
    .from(tenantMembers)
    .innerJoin(tenants, eq(tenants.id, tenantMembers.tenantId))
    .where(and(tenantPredicate, eq(tenantMembers.adminUserId, adminUserId)))
    .limit(1);

  return row === undefined
    ? undefined
    : { scope: tenantScopeFromRow(row.tenant), role: row.role };
}

/**
 * Resolves `/t/{slug}` for a signed-in admin user.
 *
 * One query does both jobs: it finds the tenant and proves the membership. There
 * is no intermediate state in which the tenant has been resolved but the
 * membership has not, so a handler cannot use the first without the second.
 *
 * @param db - The connection or transaction to use.
 * @param tenantSlug - The `/t/{slug}` path segment.
 * @param adminUserId - The signed-in admin user.
 * @returns The scope and role, or undefined when the tenant does not exist *or*
 *   the user is not a member - deliberately indistinguishable, so that the
 *   console cannot be used to enumerate tenant slugs.
 */
export async function resolveTenantScopeForMember(
  db: Executor,
  tenantSlug: string,
  adminUserId: string,
): Promise<MemberTenantScope | undefined> {
  return await resolveMembership(db, eq(tenants.slug, tenantSlug), adminUserId);
}

/** Resolves a tenant scope for a member by tenant identifier. */
export async function resolveTenantScopeForMemberById(
  db: Executor,
  tenantId: string,
  adminUserId: string,
): Promise<MemberTenantScope | undefined> {
  return await resolveMembership(db, eq(tenants.id, tenantId), adminUserId);
}

/** Reads one membership within the scoped tenant. */
export async function getTenantMembership(
  db: Executor,
  scope: TenantScope,
  adminUserId: string,
): Promise<TenantMember | undefined> {
  const [row] = await db
    .select()
    .from(tenantMembers)
    .where(
      and(
        eq(tenantMembers.tenantId, scope.tenantId),
        eq(tenantMembers.adminUserId, adminUserId),
      ),
    )
    .limit(1);
  return row;
}

/** A member of a tenant, with the person's details for display. */
export interface TenantMemberRow {
  readonly member: TenantMember;
  readonly user: AdminUser;
}

/** Lists the scoped tenant's members. */
export async function listTenantMembers(
  db: Executor,
  scope: TenantScope,
): Promise<readonly TenantMemberRow[]> {
  return await db
    .select({ member: tenantMembers, user: adminUsers })
    .from(tenantMembers)
    .innerJoin(adminUsers, eq(adminUsers.id, tenantMembers.adminUserId))
    .where(eq(tenantMembers.tenantId, scope.tenantId))
    .orderBy(adminUsers.email);
}

/**
 * Reads every membership of the scoped tenant and locks the rows.
 *
 * The lock is what makes the last-owner invariant hold under concurrency: two
 * simultaneous requests each demoting a different one of the tenant's two owners
 * would both see a second owner and both succeed, leaving none. Taking `FOR
 * UPDATE` over the tenant's membership rows serialises them.
 */
async function lockMemberships(
  tx: Executor,
  scope: TenantScope,
): Promise<readonly MembershipSummary[]> {
  return await tx
    .select({
      adminUserId: tenantMembers.adminUserId,
      role: tenantMembers.role,
    })
    .from(tenantMembers)
    .where(eq(tenantMembers.tenantId, scope.tenantId))
    .for("update");
}

/** The outcome of a membership change. */
export type MembershipChange<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly reason: "last-owner" | "not-a-member" };

/**
 * Adds a member, or changes an existing member's role.
 *
 * Written as an upsert because "invite" and "change role" are the same intent
 * from the console's point of view, and because a read-then-branch would let two
 * concurrent invitations of the same person fail with a primary key violation
 * that means nothing to the operator.
 *
 * Demoting the tenant's only owner is refused - see
 * {@link wouldRemoveLastOwner}.
 */
export async function setTenantMemberRole(
  db: Executor,
  scope: TenantScope,
  adminUserId: string,
  role: TenantRole,
): Promise<MembershipChange<TenantMember>> {
  return await db.transaction(async (tx) => {
    const members = await lockMemberships(tx, scope);
    if (wouldRemoveLastOwner(members, adminUserId, role)) {
      return { ok: false, reason: "last-owner" };
    }

    const rows = await tx
      .insert(tenantMembers)
      .values({ tenantId: scope.tenantId, adminUserId, role })
      .onConflictDoUpdate({
        target: [tenantMembers.tenantId, tenantMembers.adminUserId],
        set: { role },
      })
      .returning();

    return { ok: true, value: requireRow(rows, "upsert into tenant_members") };
  });
}

/**
 * Removes a member from the scoped tenant.
 *
 * Removing the last owner is refused, for the same reason as demoting them.
 *
 * @returns What happened, so the console can explain a refusal.
 */
export async function removeTenantMember(
  db: Executor,
  scope: TenantScope,
  adminUserId: string,
): Promise<MembershipChange<void>> {
  return await db.transaction(async (tx) => {
    const members = await lockMemberships(tx, scope);
    if (!members.some((member) => member.adminUserId === adminUserId)) {
      return { ok: false, reason: "not-a-member" };
    }
    if (wouldRemoveLastOwner(members, adminUserId, null)) {
      return { ok: false, reason: "last-owner" };
    }

    await tx
      .delete(tenantMembers)
      .where(
        and(
          eq(tenantMembers.tenantId, scope.tenantId),
          eq(tenantMembers.adminUserId, adminUserId),
        ),
      );

    return { ok: true, value: undefined };
  });
}
