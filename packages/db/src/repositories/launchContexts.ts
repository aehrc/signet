/**
 * Single-use launch handles.
 *
 * An EHR mints a handle, hands the opaque value to the app in the `launch`
 * parameter, and the app presents it at `/authorize`. Redemption is a conditional
 * `UPDATE ... WHERE consumed_at IS NULL RETURNING`, so two apps racing on the same
 * handle cannot both obtain the context: the database decides, once.
 *
 * The handle is stored only as a digest. Signet cannot reproduce it, which is why
 * `POST /launch-context` returns it exactly once.
 *
 * Author: John Grimes
 */

import { and, eq, gt, isNull, lte, or } from "drizzle-orm";

import { classifyLaunchHandleRefusal } from "./predicates.js";
import { firstRow, requireRow } from "./rows.js";
import { databaseNow, TenantScopeViolationError } from "./scope.js";
import { nowValue } from "./time.js";
import { launchContexts } from "../schema/runtime.js";

import type { Executor } from "./executor.js";
import type { LaunchHandleRefusal } from "./predicates.js";
import type { ClientScope, EndpointScope } from "./scope.js";
import type { LaunchContextRow } from "../schema/runtime.js";
import type { LaunchContext } from "@signet/core";

/** What is needed to mint a launch handle. */
export interface LaunchContextInput {
  /** SHA-256 of the opaque handle. The handle itself is never stored. */
  readonly handleHash: string;
  readonly context: LaunchContext;
  readonly expiresAt: Date;
  /** Who minted it: an admin user, an API token or an EHR client. */
  readonly createdBy?: string | null;
  /**
   * Restricts redemption to one client.
   *
   * A {@link ClientScope} rather than an identifier, so that a handle cannot be
   * bound to a client belonging to another endpoint.
   */
  readonly boundTo?: ClientScope;
}

/**
 * Mints a launch handle on the scoped endpoint.
 *
 * Binding to a client is strongly preferable and is what the console's launch
 * simulator does: an unbound handle can be redeemed by whichever app presents it
 * first, which is only acceptable when the EHR does not know which app the user
 * is about to launch.
 */
export async function createLaunchContext(
  db: Executor,
  scope: EndpointScope,
  input: LaunchContextInput,
): Promise<LaunchContextRow> {
  if (
    input.boundTo !== undefined &&
    input.boundTo.endpointId !== scope.endpointId
  ) {
    throw new TenantScopeViolationError(
      `client ${input.boundTo.clientRowId} is not on endpoint ${scope.endpointId}`,
    );
  }

  const rows = await db
    .insert(launchContexts)
    .values({
      endpointId: scope.endpointId,
      handleHash: input.handleHash,
      context: input.context,
      createdBy: input.createdBy ?? null,
      clientId: input.boundTo?.clientRowId ?? null,
      expiresAt: input.expiresAt,
    })
    .returning();

  return requireRow(rows, "insert into launch_contexts");
}

/** The outcome of redeeming a launch handle. */
export type LaunchContextRedemption =
  | { readonly ok: true; readonly launch: LaunchContextRow }
  | { readonly ok: false; readonly reason: LaunchHandleRefusal };

/**
 * Redeems a launch handle for the scoped client.
 *
 * The claim is one statement. Every condition - the right endpoint, unconsumed,
 * unexpired, and either unbound or bound to this client - is in its `WHERE`
 * clause, so there is no window between checking and consuming, and no path by
 * which a caller can act on a handle it did not claim.
 *
 * A failed claim is explained by a second read, which is a diagnosis rather than
 * a decision: whatever it says, nothing has been redeemed.
 */
export async function consumeLaunchContext(
  db: Executor,
  scope: ClientScope,
  handleHash: string,
  now?: Date,
): Promise<LaunchContextRedemption> {
  return await db.transaction(async (tx) => {
    const claimed = await tx
      .update(launchContexts)
      .set({ consumedAt: nowValue(now) })
      .where(
        and(
          eq(launchContexts.handleHash, handleHash),
          eq(launchContexts.endpointId, scope.endpointId),
          isNull(launchContexts.consumedAt),
          gt(launchContexts.expiresAt, nowValue(now)),
          or(
            isNull(launchContexts.clientId),
            eq(launchContexts.clientId, scope.clientRowId),
          ),
        ),
      )
      .returning();

    const launch = firstRow(claimed);
    if (launch !== undefined) {
      return { ok: true, launch };
    }

    const existing = await findLaunchContext(tx, scope, handleHash);
    const at = now ?? (await databaseNow(tx));
    return {
      ok: false,
      reason: classifyLaunchHandleRefusal(existing, scope.clientRowId, at),
    };
  });
}

/**
 * Reads a launch handle by digest, without redeeming it.
 *
 * Endpoint-scoped: a handle minted on another endpoint must read as absent, not
 * as a handle that then fails a later check.
 */
export async function findLaunchContext(
  db: Executor,
  scope: EndpointScope,
  handleHash: string,
): Promise<LaunchContextRow | undefined> {
  const [row] = await db
    .select()
    .from(launchContexts)
    .where(
      and(
        eq(launchContexts.handleHash, handleHash),
        eq(launchContexts.endpointId, scope.endpointId),
      ),
    )
    .limit(1);
  return row;
}

/**
 * Deletes launch handles that can no longer be redeemed.
 *
 * Sweeps take no scope, and that is not an oversight. The predicate is `expires_at
 * <= now()`, which is a property of the row rather than of the caller: it can only
 * ever remove rows that are already unusable, and it returns a count rather than
 * any data. A scope would have to be manufactured from nowhere for a scheduled job
 * that has no tenant, and manufacturing scopes is precisely what the scope types
 * exist to prevent.
 *
 * @returns How many rows were deleted.
 */
export async function deleteExpiredLaunchContexts(
  db: Executor,
  now?: Date,
): Promise<number> {
  const rows = await db
    .delete(launchContexts)
    .where(lte(launchContexts.expiresAt, nowValue(now)))
    .returning({ id: launchContexts.id });
  return rows.length;
}
