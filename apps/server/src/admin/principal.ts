/**
 * Who is calling the admin API.
 *
 * Two kinds of caller, with deliberately different authority models. A person
 * signs in and holds whatever role their `tenant_members` row gives them in each
 * tenant they belong to — so the same session may be an owner of one tenant and a
 * viewer of another. A personal access token names *one* tenant and carries a role
 * of its own, which may be narrower than its creator's: a script that only reads
 * the audit log should hold a viewer token even if an owner minted it.
 *
 * The distinction is kept in the type rather than flattened into a common shape,
 * because the two resolve their tenant differently and a handler that could not
 * tell them apart would have to guess. The one thing they share is how they appear
 * in the audit trail, which is what {@link principalActor} produces.
 */

import type { AdminUser, ApiToken, AuditActor, TenantScope } from "@signet/db";

/** A signed-in person, holding a browser session. */
export interface AdminUserPrincipal {
  readonly kind: "admin-user";
  readonly user: AdminUser;
  /** Digest of the presented cookie, so sign-out can revoke exactly this one. */
  readonly sessionTokenHash: string;
}

/** A script holding a personal access token, fixed to one tenant. */
export interface ApiTokenPrincipal {
  readonly kind: "api-token";
  readonly token: ApiToken;
  /** The tenant the token names. A token cannot act on any other. */
  readonly scope: TenantScope;
  readonly role: ApiToken["role"];
}

/** An authenticated admin API caller. */
export type AdminPrincipal = AdminUserPrincipal | ApiTokenPrincipal;

/**
 * How a principal appears in the audit trail.
 *
 * The display name is copied into the event at write time, so an event stays
 * readable after the account or token is deleted — which is why a token's name is
 * carried here rather than only its identifier.
 *
 * @param principal - The authenticated caller.
 */
export function principalActor(principal: AdminPrincipal): AuditActor {
  return principal.kind === "admin-user"
    ? {
        type: "admin-user",
        id: principal.user.id,
        displayName: principal.user.displayName,
      }
    : {
        type: "api-token",
        id: principal.token.id,
        displayName: principal.token.name,
      };
}

/**
 * The admin user identifier to record as the author of a created row.
 *
 * Null for a token, because `created_by` references `admin_users` and a token is
 * not a person. The audit event still names the token, so authorship is not lost —
 * it simply is not expressible as a foreign key.
 *
 * @param principal - The authenticated caller.
 */
export function principalAdminUserId(principal: AdminPrincipal): string | null {
  return principal.kind === "admin-user" ? principal.user.id : null;
}
