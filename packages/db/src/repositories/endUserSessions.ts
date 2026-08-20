/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * End users' browser sessions on an endpoint.
 *
 * These exist for the management page, and only for it. An end user in the middle of
 * an authorization is tracked by an `authorization_sessions` row; an end user
 * reviewing which apps hold access to their record is not in the middle of anything,
 * so they need a session of their own.
 *
 * Every function is endpoint-scoped, so a session on one endpoint cannot resolve on
 * another even though both may belong to the same tenant. The accounts are separate
 * rows with separate passwords, and treating a session as portable between them would
 * make one password admit the holder to both.
 *
 * As everywhere else in this directory, the cookie is stored as a digest and every
 * liveness condition is applied in SQL, so a caller cannot obtain the row and then
 * forget to check one of them.
 *
 * Author: John Grimes
 */

import { and, eq, gt, isNull, sql } from "drizzle-orm";

import { firstRow, requireRow } from "./rows.js";
import { executorFor } from "./scope.js";
import { nowValue } from "./time.js";
import { endUsers } from "../schema/endpoints.js";
import { endUserSessions } from "../schema/runtime.js";

import type { Executor } from "./executor.js";
import type { BoundEndpointScope } from "./scope.js";
import type { EndUser } from "../schema/endpoints.js";
import type { EndUserSession, NewEndUserSession } from "../schema/runtime.js";

/** The caller-supplied half of a new end user session. */
export type EndUserSessionInput = Pick<
  NewEndUserSession,
  "endUserId" | "tokenHash" | "expiresAt" | "ip" | "userAgent"
>;

/** Opens a session for a cookie whose digest is `tokenHash`. */
export async function createEndUserSession(
  scope: BoundEndpointScope,
  input: EndUserSessionInput,
): Promise<EndUserSession> {
  const rows = await executorFor(scope)
    .insert(endUserSessions)
    .values({ ...input, endpointId: scope.endpointId })
    .returning();
  return requireRow(rows, "insert into end_user_sessions");
}

/** An authenticated end user and the session they hold. */
export interface AuthenticatedEndUser {
  readonly session: EndUserSession;
  readonly user: EndUser;
}

/**
 * Resolves a session cookie to the person holding it.
 *
 * Five conditions, all in SQL: the digest matches, the session belongs to this
 * endpoint, it is neither revoked nor expired, and the account itself is not
 * disabled. The join to `end_users` is what makes disabling an account take effect on
 * the next request rather than at the next sign-in.
 */
export async function findLiveEndUserSession(
  scope: BoundEndpointScope,
  tokenHash: string,
  now?: Date,
): Promise<AuthenticatedEndUser | undefined> {
  const rows = await executorFor(scope)
    .select({ session: endUserSessions, user: endUsers })
    .from(endUserSessions)
    .innerJoin(endUsers, eq(endUsers.id, endUserSessions.endUserId))
    .where(
      and(
        eq(endUserSessions.tokenHash, tokenHash),
        eq(endUserSessions.endpointId, scope.endpointId),
        isNull(endUserSessions.revokedAt),
        gt(endUserSessions.expiresAt, nowValue(now)),
        isNull(endUsers.disabledAt),
      ),
    )
    .limit(1);

  return firstRow(rows);
}

/**
 * Revokes one session.
 *
 * @returns Whether a live session was revoked, so signing out twice is
 *   distinguishable from signing out once.
 */
export async function revokeEndUserSession(
  scope: BoundEndpointScope,
  tokenHash: string,
  now?: Date,
): Promise<boolean> {
  const rows = await executorFor(scope)
    .update(endUserSessions)
    .set({ revokedAt: nowValue(now) })
    .where(
      and(
        eq(endUserSessions.tokenHash, tokenHash),
        eq(endUserSessions.endpointId, scope.endpointId),
        isNull(endUserSessions.revokedAt),
      ),
    )
    .returning({ id: endUserSessions.id });
  return rows.length > 0;
}

/**
 * Revokes every live session belonging to one end user.
 *
 * Used when an account is disabled or its password changed under suspicion: the
 * session join already stops a disabled account, and this closes the window for one
 * whose credential is believed compromised.
 *
 * @returns How many sessions were revoked.
 */
export async function revokeEndUserSessionsFor(
  scope: BoundEndpointScope,
  endUserId: string,
  now?: Date,
): Promise<number> {
  const rows = await executorFor(scope)
    .update(endUserSessions)
    .set({ revokedAt: nowValue(now) })
    .where(
      and(
        eq(endUserSessions.endpointId, scope.endpointId),
        eq(endUserSessions.endUserId, endUserId),
        isNull(endUserSessions.revokedAt),
      ),
    )
    .returning({ id: endUserSessions.id });
  return rows.length;
}

/**
 * Deletes sessions past their expiry.
 *
 * Revoked-but-unexpired rows are kept, for the same reason the console's are: a
 * cookie presented after signing out should be refused by the `revoked_at` predicate
 * rather than by the row's absence, because the two are indistinguishable to the
 * browser and distinguishable in the audit log.
 *
 * @returns How many rows were deleted.
 */
export async function deleteExpiredEndUserSessions(
  db: Executor,
  before?: Date,
): Promise<number> {
  const rows = await db
    .delete(endUserSessions)
    .where(sql`${endUserSessions.expiresAt} <= ${nowValue(before)}`)
    .returning({ id: endUserSessions.id });
  return rows.length;
}
