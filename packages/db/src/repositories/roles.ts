/**
 * What a tenant role is allowed to do.
 *
 * The four roles form a total order, so authority is a comparison rather than a
 * matrix. Keeping that comparison here - pure, exhaustive over the enum, and unit
 * tested - means an endpoint that requires `admin` cannot be satisfied by a
 * `developer` because someone wrote `!==` where they meant `<`. The rank values
 * themselves are never persisted; only the role name is, so the ordering can be
 * changed without a migration.
 *
 * Author: John Grimes
 */

import type { TenantMember } from "../schema/tenancy.js";

/** A member's authority within a tenant. */
export type TenantRole = TenantMember["role"];

/**
 * Ordering of the roles, least authority first.
 *
 * Written as an exhaustive `Record` so that adding a role to the enum without
 * deciding where it ranks is a compile error. A new role silently ranking at
 * zero would be granted nothing, which is safe, but ranking by accident at the
 * top would not - and the type system cannot tell the difference, so it refuses
 * both.
 */
const ROLE_RANK: Readonly<Record<TenantRole, number>> = {
  viewer: 0,
  developer: 1,
  admin: 2,
  owner: 3,
};

/** Every role, ordered from least to most authority. */
export const TENANT_ROLES: readonly TenantRole[] = (
  Object.keys(ROLE_RANK) as TenantRole[]
).toSorted((a, b) => ROLE_RANK[a] - ROLE_RANK[b]);

/**
 * Whether a held role satisfies a requirement.
 *
 * @param held - The role the member actually has.
 * @param required - The minimum the operation demands.
 */
export function roleAtLeast(held: TenantRole, required: TenantRole): boolean {
  return ROLE_RANK[held] >= ROLE_RANK[required];
}

/**
 * Whether a role may change tenant configuration.
 *
 * `developer` is deliberately below this line. A developer may register and
 * manage their own clients, but endpoints, keys, policies and membership decide
 * what tokens the whole tenant issues, and those belong to an administrator.
 */
export function canAdministerTenant(held: TenantRole): boolean {
  return roleAtLeast(held, "admin");
}

/**
 * Whether a role may alter anything at all.
 *
 * A `viewer` is read-only everywhere, including on its own clients.
 */
export function canWrite(held: TenantRole): boolean {
  return roleAtLeast(held, "developer");
}

/** A membership as the last-owner check sees it. */
export interface MembershipSummary {
  readonly adminUserId: string;
  readonly role: TenantRole;
}

/**
 * Whether a change would leave a tenant with no owner.
 *
 * A tenant with no owner cannot grant membership to anybody, so it is
 * permanently unadministrable - the only remedy is a platform operator editing
 * the database. Removal and demotion are the same hazard, so they are the same
 * check: `nextRole` is null for a removal and the new role for a change.
 *
 * Pure, because it is the kind of condition that is easy to get right for the
 * obvious case (one owner, being removed) and wrong for the others: a member who
 * is not an owner, an owner being *promoted* to owner, and a second owner
 * existing all have to leave the tenant administrable.
 */
export function wouldRemoveLastOwner(
  members: readonly MembershipSummary[],
  targetAdminUserId: string,
  nextRole: TenantRole | null,
): boolean {
  if (nextRole === "owner") {
    return false;
  }

  const remainingOwners = members.filter(
    (member) =>
      member.role === "owner" && member.adminUserId !== targetAdminUserId,
  );

  return (
    remainingOwners.length === 0 &&
    members.some(
      (member) =>
        member.adminUserId === targetAdminUserId && member.role === "owner",
    )
  );
}
