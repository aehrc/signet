/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Passkeys on console identities, and the challenges their ceremonies consume.
 *
 * Not tenant-scoped, for the reason `./adminUsers.ts` is not: a passkey hangs off a
 * person, and a person may administer several tenants. Sign-in resolves the account
 * from the credential the authenticator presents, which necessarily happens before
 * any tenant is known - so both tables are exempt from the isolation policies and
 * this module is declared in `./unscoped.ts` with that reason.
 *
 * Two properties here are the database's rather than the caller's, and both are that
 * way because a check in application code is a check two concurrent requests can
 * each pass:
 *
 *   - The ten-per-account cap. Counting and inserting happen in one transaction that
 *     takes a row lock on the account first, so two registrations arriving together
 *     are serialised rather than both seeing nine.
 *   - Single-use challenges. Consumption is one `DELETE … RETURNING` with the expiry
 *     in the same predicate, so a replayed challenge finds nothing and an expired one
 *     cannot be spent by a caller whose clock disagrees.
 *
 * Nothing here holds a secret. A WebAuthn public key is not one, and a challenge is a
 * random value that grants nothing on its own; see the columns in
 * `../schema/tenancy.ts`.
 *
 * Author: John Grimes
 */

import { MAX_PASSKEYS_PER_ACCOUNT } from "@signet/core";
import { and, asc, eq, gt, or, sql } from "drizzle-orm";

import { isUniqueViolation } from "./errors.js";
import { firstRow, requireRow } from "./rows.js";
import { nowValue } from "./time.js";
import {
  adminPasskeyChallenges,
  adminPasskeys,
  adminUsers,
} from "../schema/tenancy.js";

import type { Executor } from "./executor.js";
import type {
  AdminPasskey,
  AdminPasskeyChallenge,
  AdminUser,
  NewAdminPasskey,
} from "../schema/tenancy.js";

/** What a ceremony challenge was minted for. */
export type PasskeyChallengePurpose = "registration" | "authentication";

/** The caller-supplied half of a registered passkey. */
export type AdminPasskeyInput = Pick<
  NewAdminPasskey,
  | "adminUserId"
  | "credentialId"
  | "publicKey"
  | "counter"
  | "transports"
  | "name"
>;

/**
 * The outcome of a registration.
 *
 * A result rather than a thrown error, because both refusals are ordinary answers
 * the API turns into a status: the account is full, or the authenticator is already
 * registered somewhere.
 */
export type AdminPasskeyInsert =
  | { readonly ok: true; readonly passkey: AdminPasskey }
  | {
      readonly ok: false;
      readonly reason: "cap-reached" | "already-registered";
    };

/** A registered passkey and the account it belongs to. */
export interface AdminPasskeyOwner {
  readonly passkey: AdminPasskey;
  readonly user: AdminUser;
}

/**
 * Lists an account's passkeys, oldest first.
 *
 * Oldest first because the list reads as a history of what was added, and the dates
 * beside each row are what an operator uses to recognise the device they are about
 * to remove.
 *
 * @param db - The connection or transaction to use.
 * @param adminUserId - Whose passkeys to list.
 */
export async function listAdminPasskeys(
  db: Executor,
  adminUserId: string,
): Promise<readonly AdminPasskey[]> {
  return await db
    .select()
    .from(adminPasskeys)
    .where(eq(adminPasskeys.adminUserId, adminUserId))
    .orderBy(asc(adminPasskeys.createdAt), asc(adminPasskeys.id));
}

/**
 * Registers a passkey, refusing once the account is full.
 *
 * The count and the insert share a transaction, and the account's row is locked
 * before the count is taken - without that, two ceremonies completing together would
 * both count nine and the account would end up with eleven. The lock is on
 * `admin_users` rather than on the passkeys themselves because the thing being
 * serialised is "how many does this account have", which no existing row represents.
 *
 * A duplicate credential identifier is left to the unique index rather than checked
 * first, for the same reason: a check that passed a moment before the insert is not
 * a check at all.
 *
 * @param db - The connection to open the transaction on.
 * @param input - The credential as the ceremony reported it, and its name.
 * @returns The stored row, or why it was refused.
 */
export async function insertAdminPasskey(
  db: Executor,
  input: AdminPasskeyInput,
): Promise<AdminPasskeyInsert> {
  try {
    return await db.transaction(async (tx) => {
      // Serialises concurrent registrations for one account. Nothing is written to
      // the row; the lock is the point.
      await tx
        .select({ id: adminUsers.id })
        .from(adminUsers)
        .where(eq(adminUsers.id, input.adminUserId))
        .for("update");

      const counted = await tx
        .select({ held: sql<number>`count(*)::int` })
        .from(adminPasskeys)
        .where(eq(adminPasskeys.adminUserId, input.adminUserId));

      if ((counted[0]?.held ?? 0) >= MAX_PASSKEYS_PER_ACCOUNT) {
        return { ok: false, reason: "cap-reached" } as const;
      }

      const rows = await tx.insert(adminPasskeys).values(input).returning();
      return {
        ok: true,
        passkey: requireRow(rows, "insert into admin_passkeys"),
      } as const;
    });
  } catch (error) {
    if (isUniqueViolation(error, "admin_passkeys_credential_id_unique")) {
      return { ok: false, reason: "already-registered" };
    }
    throw error;
  }
}

/**
 * Resolves a credential identifier to its passkey and the account holding it.
 *
 * Both in one query, because sign-in decides on both together: the account's
 * `disabled_at` is as much a reason to refuse as an unknown credential, and reading
 * them separately would invite a caller to check one and not the other.
 *
 * @param db - The connection or transaction to use.
 * @param credentialId - The base64url identifier the authenticator presented.
 * @returns The passkey and its owner, or nothing when no account registered it.
 */
export async function findAdminPasskeyByCredentialId(
  db: Executor,
  credentialId: string,
): Promise<AdminPasskeyOwner | undefined> {
  const rows = await db
    .select({ passkey: adminPasskeys, user: adminUsers })
    .from(adminPasskeys)
    .innerJoin(adminUsers, eq(adminUsers.id, adminPasskeys.adminUserId))
    .where(eq(adminPasskeys.credentialId, credentialId))
    .limit(1);

  return firstRow(rows);
}

/**
 * Records a successful sign-in against a passkey.
 *
 * The counter condition is in the statement rather than in the caller, so the write
 * cannot be the one that accepts a counter the policy would refuse. It mirrors
 * `counterAccepted` in `@signet/core`: a stored zero means an authenticator that does
 * not count, and everything else must strictly advance.
 *
 * @param db - The connection or transaction to use.
 * @param passkeyId - The passkey that was presented.
 * @param counter - What the authenticator reported.
 * @param now - The instant to stamp. Defaults to the database's own clock.
 * @returns Whether the row was updated, which is false for a counter that stalled.
 */
export async function recordAdminPasskeyUse(
  db: Executor,
  passkeyId: string,
  counter: number,
  now?: Date,
): Promise<boolean> {
  const rows = await db
    .update(adminPasskeys)
    .set({ counter, lastUsedAt: nowValue(now) })
    .where(
      and(
        eq(adminPasskeys.id, passkeyId),
        or(
          eq(adminPasskeys.counter, 0),
          gt(sql`${counter}`, adminPasskeys.counter),
        ),
      ),
    )
    .returning({ id: adminPasskeys.id });

  return rows.length > 0;
}

/**
 * Removes one of an account's own passkeys.
 *
 * Scoped to the owner in the statement, so another account's identifier matches
 * nothing. That is also what lets the API answer "no such passkey" without deciding
 * whether to disclose that somebody else holds it.
 *
 * @param db - The connection or transaction to use.
 * @param adminUserId - The account the passkey must belong to.
 * @param passkeyId - Which one to remove.
 * @returns Whether a row was removed, so removing twice is distinguishable.
 */
export async function removeAdminPasskey(
  db: Executor,
  adminUserId: string,
  passkeyId: string,
): Promise<boolean> {
  const rows = await db
    .delete(adminPasskeys)
    .where(
      and(
        eq(adminPasskeys.id, passkeyId),
        eq(adminPasskeys.adminUserId, adminUserId),
      ),
    )
    .returning({ id: adminPasskeys.id });

  return rows.length > 0;
}

/** What a new ceremony challenge is made of. */
export interface AdminPasskeyChallengeInput {
  /** The random value, base64url, as it will appear in the ceremony options. */
  readonly challenge: string;
  readonly purpose: PasskeyChallengePurpose;
  /**
   * The account a registration challenge was minted for.
   *
   * Null for an authentication challenge, which is issued before anybody has said
   * who they are.
   */
  readonly adminUserId: string | null;
  readonly expiresAt: Date;
}

/** Issues a ceremony challenge. */
export async function createAdminPasskeyChallenge(
  db: Executor,
  input: AdminPasskeyChallengeInput,
): Promise<AdminPasskeyChallenge> {
  const rows = await db
    .insert(adminPasskeyChallenges)
    .values(input)
    .returning();
  return requireRow(rows, "insert into admin_passkey_challenges");
}

/**
 * Spends a ceremony challenge, exactly once.
 *
 * One `DELETE … RETURNING` carrying every condition: the value, the purpose it was
 * minted for, and an expiry that has not passed. A challenge that was never issued,
 * one already spent and one that has expired are therefore the same answer - nothing
 * - and two ceremonies presenting the same value cannot both be given the row.
 *
 * Refusing the wrong purpose matters on its own: a registration challenge is minted
 * behind a password check, and accepting one for a sign-in would let it be spent for
 * something it was not authorised for.
 *
 * @param db - The connection or transaction to use.
 * @param challenge - The value the browser signed over.
 * @param purpose - The ceremony it must have been minted for.
 * @param now - The instant to compare the expiry against. Defaults to the
 *   database's own clock, which is the one that should decide.
 * @returns The consumed row, or nothing.
 */
export async function consumeAdminPasskeyChallenge(
  db: Executor,
  challenge: string,
  purpose: PasskeyChallengePurpose,
  now?: Date,
): Promise<AdminPasskeyChallenge | undefined> {
  const rows = await db
    .delete(adminPasskeyChallenges)
    .where(
      and(
        eq(adminPasskeyChallenges.challenge, challenge),
        eq(adminPasskeyChallenges.purpose, purpose),
        gt(adminPasskeyChallenges.expiresAt, nowValue(now)),
      ),
    )
    .returning();

  return firstRow(rows);
}

/**
 * Deletes challenges nobody spent before they expired.
 *
 * An expired row grants nothing - `consumeAdminPasskeyChallenge` refuses it either
 * way - so this removes storage rather than permission, which is what makes it safe
 * to run across every account from the scheduled sweep.
 *
 * @param db - The connection or transaction to use.
 * @param before - The cut-off. Defaults to the database's own clock.
 * @returns How many rows were deleted.
 */
export async function deleteExpiredAdminPasskeyChallenges(
  db: Executor,
  before?: Date,
): Promise<number> {
  const rows = await db
    .delete(adminPasskeyChallenges)
    .where(sql`${adminPasskeyChallenges.expiresAt} <= ${nowValue(before)}`)
    .returning({ id: adminPasskeyChallenges.id });

  return rows.length;
}
