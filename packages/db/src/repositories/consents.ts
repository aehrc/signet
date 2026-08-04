/**
 * Remembered authorisations.
 *
 * A consent row lets an endpoint in `remember` mode skip the prompt for an app the
 * user has already approved. It is therefore a *permission* record, and the query
 * that reads it decides whether a user sees a consent screen - so the scope
 * comparison is the caller's responsibility and is deliberately not done here:
 * `@signet/core`'s `isSubsetOf` decides whether what is now being asked for falls
 * within what was consented to. A repository predicate matching on scope strings
 * would treat `patient/*.rs` and `patient/Observation.r` as unrelated, and the user
 * would be re-prompted for less than they had already granted, or worse, not
 * prompted for more.
 *
 * Revocation is never a delete: the end user's management page sets `revoked_at`,
 * so the record that consent once existed survives.
 *
 * Author: John Grimes
 */

import { and, desc, eq, gt, isNull, lte, or } from "drizzle-orm";

import { requireRow } from "./rows.js";
import { nowValue } from "./time.js";
import { clients } from "../schema/clients.js";
import { consents } from "../schema/runtime.js";

import type { Executor } from "./executor.js";
import type { ClientScope, EndpointScope } from "./scope.js";
import type { Client } from "../schema/clients.js";
import type { Consent, NewConsent } from "../schema/runtime.js";

/** The caller-supplied half of a consent record. */
export type ConsentInput = Pick<
  NewConsent,
  "endUserId" | "scope" | "expiresAt"
>;

/** Records that an end user consented to the scoped client's scopes. */
export async function recordConsent(
  db: Executor,
  scope: ClientScope,
  input: ConsentInput,
): Promise<Consent> {
  const rows = await db
    .insert(consents)
    .values({
      ...input,
      endpointId: scope.endpointId,
      clientId: scope.clientRowId,
    })
    .returning();
  return requireRow(rows, "insert into consents");
}

/**
 * Lists the live consents an end user has given the scoped client.
 *
 * Newest first, and only rows that are neither revoked nor expired - a null
 * `expires_at` means a consent that does not expire, so the predicate is a
 * disjunction rather than a comparison against a default.
 *
 * Returns a list rather than one row because consent accumulates: a user may have
 * approved a narrow scope set once and a wider one later, and the caller has to be
 * able to test the request against all of them.
 */
export async function listLiveConsents(
  db: Executor,
  scope: ClientScope,
  endUserId: string,
  now?: Date,
): Promise<readonly Consent[]> {
  return await db
    .select()
    .from(consents)
    .where(
      and(
        eq(consents.endpointId, scope.endpointId),
        eq(consents.clientId, scope.clientRowId),
        eq(consents.endUserId, endUserId),
        isNull(consents.revokedAt),
        or(isNull(consents.expiresAt), gt(consents.expiresAt, nowValue(now))),
      ),
    )
    .orderBy(desc(consents.grantedAt));
}

/** A consent and the app it was given to, for the management page. */
export interface ConsentWithClient {
  readonly consent: Consent;
  readonly client: Client;
}

/**
 * Lists everything an end user has ever consented to on the scoped endpoint.
 *
 * Revoked and expired rows are included: the management page has to be able to
 * show what was revoked and when, or "revoke" would look like it had lost the
 * record rather than ended it.
 */
export async function listConsentsForEndUser(
  db: Executor,
  scope: EndpointScope,
  endUserId: string,
): Promise<readonly ConsentWithClient[]> {
  return await db
    .select({ consent: consents, client: clients })
    .from(consents)
    .innerJoin(clients, eq(clients.id, consents.clientId))
    .where(
      and(
        eq(consents.endpointId, scope.endpointId),
        eq(consents.endUserId, endUserId),
      ),
    )
    .orderBy(desc(consents.grantedAt));
}

/**
 * Revokes one consent.
 *
 * @returns Whether a live consent was revoked.
 */
export async function revokeConsent(
  db: Executor,
  scope: EndpointScope,
  consentId: string,
  now?: Date,
): Promise<boolean> {
  const rows = await db
    .update(consents)
    .set({ revokedAt: nowValue(now) })
    .where(
      and(
        eq(consents.id, consentId),
        eq(consents.endpointId, scope.endpointId),
        isNull(consents.revokedAt),
      ),
    )
    .returning({ id: consents.id });
  return rows.length > 0;
}

/**
 * Revokes every live consent an end user gave the scoped client.
 *
 * This is the "disconnect this app" button. It does not revoke the app's tokens -
 * that is a separate call, and both are needed: withdrawing consent stops the next
 * authorization, revoking tokens stops the current one.
 *
 * @returns How many consents were revoked.
 */
export async function revokeConsentsForClient(
  db: Executor,
  scope: ClientScope,
  endUserId: string,
  now?: Date,
): Promise<number> {
  const rows = await db
    .update(consents)
    .set({ revokedAt: nowValue(now) })
    .where(
      and(
        eq(consents.endpointId, scope.endpointId),
        eq(consents.clientId, scope.clientRowId),
        eq(consents.endUserId, endUserId),
        isNull(consents.revokedAt),
      ),
    )
    .returning({ id: consents.id });
  return rows.length;
}

/**
 * Deletes consents that have passed their own expiry.
 *
 * Rows with no expiry are never touched, and neither are revoked rows that have
 * not expired - a revoked consent is evidence of a decision the user made, and it
 * is the audit log's business how long that is kept, not the sweep's.
 *
 * @returns How many rows were deleted.
 */
export async function deleteExpiredConsents(
  db: Executor,
  before?: Date,
): Promise<number> {
  const rows = await db
    .delete(consents)
    .where(lte(consents.expiresAt, nowValue(before)))
    .returning({ id: consents.id });
  return rows.length;
}
