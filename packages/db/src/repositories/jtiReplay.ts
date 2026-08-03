/**
 * The `private_key_jwt` replay ledger.
 *
 * A client assertion is a signed JWT that authenticates a confidential-asymmetric
 * client. Its signature stays valid for as long as the assertion's own `exp`
 * allows, so anyone who observes one can present it again within that window — the
 * `jti` claim, recorded here, is what makes the second attempt fail.
 *
 * The composite primary key `(client_id, jti)` *is* the check. Recording is an
 * insert that either succeeds, meaning the assertion is new, or conflicts, meaning
 * it has been seen. There is no read-then-insert, because between the read and the
 * insert two concurrent presentations of the same assertion would both find
 * nothing.
 *
 * `ON CONFLICT DO NOTHING` is used rather than catching the unique violation, and
 * the difference matters: a raised constraint error aborts the surrounding
 * transaction, so every subsequent statement in the token exchange would fail with
 * `current transaction is aborted` and the real cause would be lost. Absorbing the
 * conflict keeps the transaction usable, and the empty `RETURNING` is the signal.
 *
 * @see https://hl7.org/fhir/smart-app-launch/client-confidential-asymmetric.html
 */

import { and, eq, lte } from "drizzle-orm";

import { nowValue } from "./time.js";
import { jtiReplay } from "../schema/runtime.js";

import type { Executor } from "./executor.js";
import type { ClientScope } from "./scope.js";

/**
 * What recording a `jti` decided.
 *
 * A typed result rather than an exception, because the caller must distinguish
 * three outcomes — accepted, replayed, and "the database is unavailable" — and only
 * the last is an error. Conflating the middle two would answer a replay with a 500
 * and a real fault with an authentication failure, which is the wrong response in
 * both directions.
 */
export type JtiRecord =
  { readonly status: "recorded" } | { readonly status: "already-seen" };

/**
 * Books a client assertion's `jti` against the scoped client.
 *
 * The ledger is per client, which is the correct granularity: `jti` values are only
 * required to be unique per issuer, so two clients may legitimately choose the same
 * one, and a global ledger would refuse the second as a replay.
 *
 * @param db - The connection or transaction to use.
 * @param scope - The client the assertion authenticates.
 * @param jti - The assertion's `jti` claim.
 * @param expiresAt - The assertion's own expiry. The row may be swept once the
 *   assertion could no longer be accepted anyway, which is what stops the ledger
 *   growing without bound. Passing anything later than the assertion's `exp` merely
 *   wastes storage; passing anything earlier reopens the replay window, so the
 *   caller must pass the assertion's `exp` and not a shorter interval of its own.
 */
export async function recordJti(
  db: Executor,
  scope: ClientScope,
  jti: string,
  expiresAt: Date,
): Promise<JtiRecord> {
  const rows = await db
    .insert(jtiReplay)
    .values({ clientId: scope.clientRowId, jti, expiresAt })
    .onConflictDoNothing({ target: [jtiReplay.clientId, jtiReplay.jti] })
    .returning({ jti: jtiReplay.jti });

  return rows.length > 0 ? { status: "recorded" } : { status: "already-seen" };
}

/**
 * Whether a `jti` has already been booked for the scoped client.
 *
 * For diagnostics and tests. Authentication must use {@link recordJti}: this
 * cannot be part of a check, because whatever it returns may be stale by the time
 * the caller acts on it.
 */
export async function hasSeenJti(
  db: Executor,
  scope: ClientScope,
  jti: string,
): Promise<boolean> {
  const rows = await db
    .select({ jti: jtiReplay.jti })
    .from(jtiReplay)
    .where(
      and(eq(jtiReplay.clientId, scope.clientRowId), eq(jtiReplay.jti, jti)),
    )
    .limit(1);
  return rows.length > 0;
}

/**
 * Deletes ledger entries for assertions that can no longer be presented.
 *
 * @returns How many rows were deleted.
 */
export async function deleteExpiredJtis(
  db: Executor,
  before?: Date,
): Promise<number> {
  const rows = await db
    .delete(jtiReplay)
    .where(lte(jtiReplay.expiresAt, nowValue(before)))
    .returning({ jti: jtiReplay.jti });
  return rows.length;
}
