/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Invitations to choose an end user account's password.
 *
 * An administrator creates a local account, then sends its holder a link; opening the
 * link and choosing a password redeems it. The link carries an opaque token and the
 * table stores its digest, so the console can show the link once and nothing that
 * reads the database afterwards can reconstruct it.
 *
 * Every condition that decides whether a link works is applied in SQL, as for the
 * other credentials in this directory: the digest matches, the row belongs to this
 * endpoint, it has not expired, and the account is an enabled local account. A
 * caller therefore cannot obtain the row and then forget to check one of them.
 *
 * Redemption deletes the row in the statement that finds it. Two concurrent
 * redemptions of the same link serialise on that row, and the second finds nothing.
 *
 * Author: John Grimes
 */

import { and, eq, gt, isNull, sql } from "drizzle-orm";

import { setEndUserPasswordHash } from "./endUsers.js";
import { revokeEndUserSessionsFor } from "./endUserSessions.js";
import { firstRow, requireRow } from "./rows.js";
import { executorFor } from "./scope.js";
import { nowValue } from "./time.js";
import { endUsers } from "../schema/endpoints.js";
import { endUserInvitations } from "../schema/runtime.js";

import type { Executor } from "./executor.js";
import type { BoundEndpointScope } from "./scope.js";
import type { EndUser } from "../schema/endpoints.js";
import type { EndUserInvitation } from "../schema/runtime.js";
import type { SQL } from "drizzle-orm";

/** The caller-supplied half of an invitation. */
export interface EndUserInvitationInput {
  /** The account, which the caller has already resolved on this endpoint. */
  readonly endUserId: string;
  /** SHA-256 of the token in the link. */
  readonly tokenHash: string;
  readonly expiresAt: Date;
}

/** An account and the invitation that names it. */
export interface InvitedEndUser {
  readonly user: EndUser;
  readonly invitation: EndUserInvitation;
}

/**
 * Issues an invitation, replacing any the account already has.
 *
 * The replacement is an upsert on the account, so the earlier digest is overwritten in
 * the same statement and the earlier link stops working as the new one starts.
 *
 * @param scope - The endpoint the account belongs to.
 * @param input - The account, the token's digest and the expiry.
 * @returns The stored invitation.
 */
export async function issueEndUserInvitation(
  scope: BoundEndpointScope,
  input: EndUserInvitationInput,
): Promise<EndUserInvitation> {
  const rows = await executorFor(scope)
    .insert(endUserInvitations)
    .values({ ...input, endpointId: scope.endpointId })
    .onConflictDoUpdate({
      target: endUserInvitations.endUserId,
      set: {
        tokenHash: input.tokenHash,
        expiresAt: input.expiresAt,
        createdAt: sql`now()`,
      },
    })
    .returning();
  return requireRow(rows, "upsert into end_user_invitations");
}

/**
 * Reads an account's invitation, if it has one that has not expired.
 *
 * @param scope - The endpoint the account belongs to.
 * @param endUserId - The account.
 * @param now - The instant to compare the expiry against; the database's own by default.
 * @returns The invitation, or undefined.
 */
export async function findOutstandingEndUserInvitation(
  scope: BoundEndpointScope,
  endUserId: string,
  now?: Date,
): Promise<EndUserInvitation | undefined> {
  const rows = await executorFor(scope)
    .select()
    .from(endUserInvitations)
    .where(
      and(
        eq(endUserInvitations.endpointId, scope.endpointId),
        eq(endUserInvitations.endUserId, endUserId),
        gt(endUserInvitations.expiresAt, nowValue(now)),
      ),
    )
    .limit(1);
  return firstRow(rows);
}

/**
 * The conditions under which a presented link works, short of being spent.
 *
 * The account conditions are the ones `invitationRefusal` in `@signet/core` applies
 * before a link is issued, repeated here because either may have changed since: the
 * account can be disabled after the link was sent.
 */
function usableInvitation(
  scope: BoundEndpointScope,
  tokenHash: string,
  now: Date | undefined,
): SQL | undefined {
  return and(
    eq(endUserInvitations.tokenHash, tokenHash),
    eq(endUserInvitations.endpointId, scope.endpointId),
    gt(endUserInvitations.expiresAt, nowValue(now)),
    eq(endUsers.endpointId, scope.endpointId),
    isNull(endUsers.disabledAt),
    eq(endUsers.isPersona, false),
  );
}

/**
 * Finds the account a presented link would let somebody set the password of.
 *
 * For the invitation page, which shows the invitee which account they are about to
 * claim before they choose a password. Does not spend the link.
 *
 * @param scope - The endpoint the link was presented at.
 * @param tokenHash - SHA-256 of the presented token.
 * @param now - The instant to compare the expiry against; the database's own by default.
 * @returns The account and its invitation, or undefined when the link does not work.
 */
export async function findEndUserByInvitation(
  scope: BoundEndpointScope,
  tokenHash: string,
  now?: Date,
): Promise<InvitedEndUser | undefined> {
  const rows = await executorFor(scope)
    .select({ user: endUsers, invitation: endUserInvitations })
    .from(endUserInvitations)
    .innerJoin(endUsers, eq(endUsers.id, endUserInvitations.endUserId))
    .where(usableInvitation(scope, tokenHash, now))
    .limit(1);
  return firstRow(rows);
}

/**
 * Spends a link: sets the account's password and ends its sessions.
 *
 * Must run inside one bound transaction, which `withTenantScope` provides, so that the
 * link is spent if and only if the password is set. The sessions are revoked because a
 * link is also how a forgotten or compromised password is replaced, and whoever held
 * the old password may hold a session too.
 *
 * @param scope - The endpoint the link was presented at.
 * @param tokenHash - SHA-256 of the presented token.
 * @param passwordHash - The Argon2id hash of the chosen password.
 * @param now - The instant to compare the expiry against; the database's own by default.
 * @returns The updated account, or undefined when the link does not work.
 */
export async function redeemEndUserInvitation(
  scope: BoundEndpointScope,
  tokenHash: string,
  passwordHash: string,
  now?: Date,
): Promise<EndUser | undefined> {
  const eligible = executorFor(scope)
    .select({ id: endUsers.id })
    .from(endUsers)
    .innerJoin(
      endUserInvitations,
      eq(endUserInvitations.endUserId, endUsers.id),
    )
    .where(usableInvitation(scope, tokenHash, now));

  const [claimed] = await executorFor(scope)
    .delete(endUserInvitations)
    .where(
      and(
        eq(endUserInvitations.tokenHash, tokenHash),
        eq(endUserInvitations.endpointId, scope.endpointId),
        sql`${endUserInvitations.endUserId} in ${eligible}`,
      ),
    )
    .returning({ endUserId: endUserInvitations.endUserId });
  if (claimed === undefined) {
    return undefined;
  }

  const user = await setEndUserPasswordHash(
    scope,
    claimed.endUserId,
    passwordHash,
  );
  await revokeEndUserSessionsFor(scope, claimed.endUserId, now);
  return user;
}

/**
 * Withdraws an account's outstanding invitation.
 *
 * @param scope - The endpoint the account belongs to.
 * @param endUserId - The account.
 * @param now - The instant to compare the expiry against; the database's own by default.
 * @returns Whether an outstanding invitation was withdrawn, so cancelling an expired
 *   or absent one is distinguishable from cancelling a live one.
 */
export async function cancelEndUserInvitation(
  scope: BoundEndpointScope,
  endUserId: string,
  now?: Date,
): Promise<boolean> {
  const rows = await executorFor(scope)
    .delete(endUserInvitations)
    .where(
      and(
        eq(endUserInvitations.endpointId, scope.endpointId),
        eq(endUserInvitations.endUserId, endUserId),
        gt(endUserInvitations.expiresAt, nowValue(now)),
      ),
    )
    .returning({ endUserId: endUserInvitations.endUserId });
  return rows.length > 0;
}

/**
 * Deletes invitations past their expiry, for the sweep.
 *
 * @param db - A connection with the owning identity; see `./sweep.ts`.
 * @param before - The instant to compare against; the database's own by default.
 * @returns How many rows were deleted.
 */
export async function deleteExpiredEndUserInvitations(
  db: Executor,
  before?: Date,
): Promise<number> {
  const rows = await db
    .delete(endUserInvitations)
    .where(sql`${endUserInvitations.expiresAt} <= ${nowValue(before)}`)
    .returning({ endUserId: endUserInvitations.endUserId });
  return rows.length;
}
