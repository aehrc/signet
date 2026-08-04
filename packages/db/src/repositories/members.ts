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
 * The two membership writes deliberately do not open transactions of their own any
 * more. They take a bound scope, so they are already inside the transaction that
 * declared the tenant, and that is the transaction the `FOR UPDATE` lock they rely
 * on is held for. Opening a nested one would only add a savepoint.
 *
 * Author: John Grimes
 */

import { and, eq } from "drizzle-orm";

import { wouldRemoveLastOwner } from "./roles.js";
import { tenantIdForSlug } from "./routines.js";
import { requireRow } from "./rows.js";
import {
  executorFor,
  tenantScopeFromRow,
  withDeclaredTenant,
} from "./scope.js";
import { adminUsers, tenantMembers, tenants } from "../schema/tenancy.js";

import type { Executor } from "./executor.js";
import type { MembershipSummary, TenantRole } from "./roles.js";
import type { BoundTenantScope, TenantScope } from "./scope.js";
import type { AdminUser, TenantMember } from "../schema/tenancy.js";

/** A tenant scope together with the authority the caller holds in it. */
export interface MemberTenantScope {
  readonly scope: TenantScope;
  readonly role: TenantRole;
}

/**
 * Resolves `/t/{slug}` for a signed-in admin user.
 *
 * Two steps, because the slug is all the request carries and both tables the
 * authorisation check reads are tenant-owned: the routine turns the slug into a
 * tenant identifier, and the membership join then runs inside a transaction
 * declared for it. The join is still one query, so there remains no intermediate
 * state in which the tenant has been resolved but the membership has not - a
 * handler cannot use the first without the second.
 *
 * The declaration is what makes the tenant reachable, and the membership predicate
 * is what makes it *the caller's*. Both are needed: declaring a tenant an operator
 * is not a member of yields a scope only if this join finds a row, and it will not.
 *
 * @param db - The connection to resolve on. No tenant need be declared.
 * @param tenantSlug - The `/t/{slug}` path segment.
 * @param adminUserId - The signed-in admin user.
 * @returns The scope and role, or undefined when the tenant does not exist *or*
 *   the user is not a member - deliberately indistinguishable, so that the
 *   console cannot be used to enumerate tenant slugs. Unbound, for the reason
 *   `resolveTenantScope` gives.
 */
export async function resolveTenantScopeForMember(
  db: Executor,
  tenantSlug: string,
  adminUserId: string,
): Promise<MemberTenantScope | undefined> {
  const tenantId = await tenantIdForSlug(db, tenantSlug);
  if (tenantId === undefined) {
    return undefined;
  }

  return await withDeclaredTenant(db, tenantId, async (tx) => {
    const [row] = await tx
      .select({ tenant: tenants, role: tenantMembers.role })
      .from(tenantMembers)
      .innerJoin(tenants, eq(tenants.id, tenantMembers.tenantId))
      .where(
        and(
          eq(tenantMembers.tenantId, tenantId),
          eq(tenantMembers.adminUserId, adminUserId),
        ),
      )
      .limit(1);

    return row === undefined
      ? undefined
      : { scope: tenantScopeFromRow(row.tenant), role: row.role };
  });
}

/** Reads one membership within the scoped tenant. */
export async function getTenantMembership(
  scope: BoundTenantScope,
  adminUserId: string,
): Promise<TenantMember | undefined> {
  const [row] = await executorFor(scope)
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
  scope: BoundTenantScope,
): Promise<readonly TenantMemberRow[]> {
  return await executorFor(scope)
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
 * UPDATE` over the tenant's membership rows serialises them, and it holds until
 * the transaction the scope was declared on commits - which is what the two
 * callers below rely on rather than opening a transaction of their own.
 */
async function lockMemberships(
  scope: BoundTenantScope,
): Promise<readonly MembershipSummary[]> {
  return await executorFor(scope)
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
  scope: BoundTenantScope,
  adminUserId: string,
  role: TenantRole,
): Promise<MembershipChange<TenantMember>> {
  const members = await lockMemberships(scope);
  if (wouldRemoveLastOwner(members, adminUserId, role)) {
    return { ok: false, reason: "last-owner" };
  }

  const rows = await executorFor(scope)
    .insert(tenantMembers)
    .values({ tenantId: scope.tenantId, adminUserId, role })
    .onConflictDoUpdate({
      target: [tenantMembers.tenantId, tenantMembers.adminUserId],
      set: { role },
    })
    .returning();

  return { ok: true, value: requireRow(rows, "upsert into tenant_members") };
}

/**
 * Removes a member from the scoped tenant.
 *
 * Removing the last owner is refused, for the same reason as demoting them.
 *
 * @returns What happened, so the console can explain a refusal.
 */
export async function removeTenantMember(
  scope: BoundTenantScope,
  adminUserId: string,
): Promise<MembershipChange<void>> {
  const members = await lockMemberships(scope);
  if (!members.some((member) => member.adminUserId === adminUserId)) {
    return { ok: false, reason: "not-a-member" };
  }
  if (wouldRemoveLastOwner(members, adminUserId, null)) {
    return { ok: false, reason: "last-owner" };
  }

  await executorFor(scope)
    .delete(tenantMembers)
    .where(
      and(
        eq(tenantMembers.tenantId, scope.tenantId),
        eq(tenantMembers.adminUserId, adminUserId),
      ),
    );

  return { ok: true, value: undefined };
}
