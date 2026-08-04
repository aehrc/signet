/**
 * Console identities and their browser sessions.
 *
 * This is the one part of the schema that is deliberately *not* tenant-scoped. An
 * admin user is a person, and a person may belong to several tenants; scoping the
 * identity to a tenant would mean one human holding several passwords, which
 * ends with the same password in several places. Authority within a tenant lives
 * in `tenant_members` (see `./members.ts`) - this module answers only "who is
 * this?", never "what may they do?".
 *
 * Nothing here reads or returns a credential in the clear. The password hash
 * crosses the boundary because verification happens in the caller, which holds
 * the presented password; the TOTP secret crosses it encrypted.
 *
 * Author: John Grimes
 */

import { and, eq, gt, isNull, sql } from "drizzle-orm";

import { firstRow, requireRow } from "./rows.js";
import { nowValue } from "./time.js";
import { adminSessions, adminUsers } from "../schema/tenancy.js";

import type { Executor } from "./executor.js";
import type {
  AdminSession,
  AdminUser,
  NewAdminSession,
  NewAdminUser,
} from "../schema/tenancy.js";

/** The caller-supplied half of a new console identity. */
export type AdminUserInput = Pick<
  NewAdminUser,
  "email" | "passwordHash" | "displayName"
>;

/**
 * Creates a console identity.
 *
 * The email is stored exactly as typed. Uniqueness is enforced on `lower(email)`
 * by the schema, so `A@example.org` cannot be registered alongside
 * `a@example.org`, but the address is displayed back to its owner in the form
 * they chose.
 */
export async function createAdminUser(
  db: Executor,
  input: AdminUserInput,
): Promise<AdminUser> {
  const rows = await db.insert(adminUsers).values(input).returning();
  return requireRow(rows, "insert into admin_users");
}

/**
 * Finds a console identity by email, case-insensitively.
 *
 * The predicate is written as `lower(email) = ?` to match the expression the
 * unique index is built on; a `citext` cast or an `ilike` would not use it, and
 * this is the first query of every console login.
 */
export async function findAdminUserByEmail(
  db: Executor,
  email: string,
): Promise<AdminUser | undefined> {
  const [row] = await db
    .select()
    .from(adminUsers)
    .where(eq(sql`lower(${adminUsers.email})`, email.toLowerCase()))
    .limit(1);
  return row;
}

/** Reads a console identity by identifier. */
export async function getAdminUser(
  db: Executor,
  adminUserId: string,
): Promise<AdminUser | undefined> {
  const [row] = await db
    .select()
    .from(adminUsers)
    .where(eq(adminUsers.id, adminUserId))
    .limit(1);
  return row;
}

/** Records a successful sign-in. */
export async function recordAdminLogin(
  db: Executor,
  adminUserId: string,
  now?: Date,
): Promise<void> {
  await db
    .update(adminUsers)
    .set({ lastLoginAt: nowValue(now) })
    .where(eq(adminUsers.id, adminUserId));
}

/**
 * Replaces a console identity's password hash.
 *
 * Existing sessions are deliberately left alone: revoking them is a separate,
 * explicitly audited decision, and a password change forced by an operator
 * should not silently sign the person out of the tab they are typing into. The
 * console calls {@link revokeAdminSessionsForUser} alongside this when the
 * change was prompted by a suspected compromise.
 */
export async function setAdminPasswordHash(
  db: Executor,
  adminUserId: string,
  passwordHash: string,
): Promise<void> {
  await db
    .update(adminUsers)
    .set({ passwordHash })
    .where(eq(adminUsers.id, adminUserId));
}

/**
 * Stores or clears an encrypted TOTP secret.
 *
 * @param db - The connection or transaction to use.
 * @param adminUserId - The identity to enrol or unenrol.
 * @param secretEncrypted - The AES-256-GCM envelope, or null to unenrol.
 */
export async function setAdminTotpSecret(
  db: Executor,
  adminUserId: string,
  secretEncrypted: string | null,
): Promise<void> {
  await db
    .update(adminUsers)
    .set({ totpSecretEncrypted: secretEncrypted })
    .where(eq(adminUsers.id, adminUserId));
}

/**
 * Locks or unlocks a console identity.
 *
 * Disabling is not deletion: the row survives so that its audit trail keeps a
 * name attached to it, and `findLiveAdminSession` stops honouring the identity's
 * existing cookies immediately.
 */
export async function setAdminUserDisabled(
  db: Executor,
  adminUserId: string,
  disabled: boolean,
  now?: Date,
): Promise<AdminUser | undefined> {
  const [row] = await db
    .update(adminUsers)
    .set({ disabledAt: disabled ? nowValue(now) : null })
    .where(eq(adminUsers.id, adminUserId))
    .returning();
  return row;
}

/**
 * Deletes a console identity outright.
 *
 * Almost always the wrong operation: {@link setAdminUserDisabled} locks the
 * account out immediately while keeping a name attached to its audit trail, which
 * is what an operator revoking somebody's access wants. This exists for the case
 * disabling cannot serve - erasing a person's record on request - and takes the
 * consequences with it. Sessions and memberships cascade; audit events do not,
 * because `actor_id` carries no foreign key, so the trail survives with the
 * identifier and the display name that were copied into each event.
 *
 * @returns Whether an identity was deleted.
 */
export async function deleteAdminUser(
  db: Executor,
  adminUserId: string,
): Promise<boolean> {
  const rows = await db
    .delete(adminUsers)
    .where(eq(adminUsers.id, adminUserId))
    .returning({ id: adminUsers.id });
  return rows.length > 0;
}

/** The caller-supplied half of a new console session. */
export type AdminSessionInput = Pick<
  NewAdminSession,
  "adminUserId" | "tokenHash" | "expiresAt" | "ip" | "userAgent"
>;

/** Opens a console session for a cookie whose digest is `tokenHash`. */
export async function createAdminSession(
  db: Executor,
  input: AdminSessionInput,
): Promise<AdminSession> {
  const rows = await db.insert(adminSessions).values(input).returning();
  return requireRow(rows, "insert into admin_sessions");
}

/** An authenticated console session and the person it belongs to. */
export interface AuthenticatedAdmin {
  readonly session: AdminSession;
  readonly user: AdminUser;
}

/**
 * Resolves a session cookie to the person holding it.
 *
 * Every condition is applied in SQL - not revoked, not expired, and the identity
 * itself not disabled - so that there is exactly one query a request must pass
 * and no opportunity for a caller to check three of the four. In particular the
 * join to `admin_users` is what makes disabling an account take effect on the
 * next request rather than at the next login.
 */
export async function findLiveAdminSession(
  db: Executor,
  tokenHash: string,
  now?: Date,
): Promise<AuthenticatedAdmin | undefined> {
  const rows = await db
    .select({ session: adminSessions, user: adminUsers })
    .from(adminSessions)
    .innerJoin(adminUsers, eq(adminUsers.id, adminSessions.adminUserId))
    .where(
      and(
        eq(adminSessions.tokenHash, tokenHash),
        isNull(adminSessions.revokedAt),
        gt(adminSessions.expiresAt, nowValue(now)),
        isNull(adminUsers.disabledAt),
      ),
    )
    .limit(1);

  return firstRow(rows);
}

/**
 * Revokes one session.
 *
 * @returns Whether a live session was revoked, so that signing out twice is
 *   distinguishable from signing out once.
 */
export async function revokeAdminSession(
  db: Executor,
  tokenHash: string,
  now?: Date,
): Promise<boolean> {
  const rows = await db
    .update(adminSessions)
    .set({ revokedAt: nowValue(now) })
    .where(
      and(
        eq(adminSessions.tokenHash, tokenHash),
        isNull(adminSessions.revokedAt),
      ),
    )
    .returning({ id: adminSessions.id });
  return rows.length > 0;
}

/**
 * Revokes every live session belonging to one identity.
 *
 * @returns How many sessions were revoked.
 */
export async function revokeAdminSessionsForUser(
  db: Executor,
  adminUserId: string,
  now?: Date,
): Promise<number> {
  const rows = await db
    .update(adminSessions)
    .set({ revokedAt: nowValue(now) })
    .where(
      and(
        eq(adminSessions.adminUserId, adminUserId),
        isNull(adminSessions.revokedAt),
      ),
    )
    .returning({ id: adminSessions.id });
  return rows.length;
}

/**
 * Deletes console sessions past their expiry.
 *
 * Revoked-but-unexpired rows are kept, so that a user who signs out and then
 * presents the same cookie again is refused by the `revoked_at` predicate rather
 * than by the row's absence. The two are indistinguishable to the browser and
 * distinguishable in the audit log, which is the point.
 *
 * @returns How many rows were deleted.
 */
export async function deleteExpiredAdminSessions(
  db: Executor,
  before?: Date,
): Promise<number> {
  const rows = await db
    .delete(adminSessions)
    .where(sql`${adminSessions.expiresAt} <= ${nowValue(before)}`)
    .returning({ id: adminSessions.id });
  return rows.length;
}

/** Lists an identity's sessions, newest first, for the security page. */
export async function listAdminSessions(
  db: Executor,
  adminUserId: string,
): Promise<readonly AdminSession[]> {
  return await db
    .select()
    .from(adminSessions)
    .where(eq(adminSessions.adminUserId, adminUserId))
    .orderBy(sql`${adminSessions.createdAt} desc`);
}
