/**
 * The self-serve client registration queue.
 *
 * A decision is claimed with a conditional `UPDATE ... WHERE status = 'pending'`
 * before the client is created. Two administrators pressing Approve at the same
 * moment therefore produce one client, not two: the second update matches no row
 * and the transaction returns `already-decided`. A read-then-write would have
 * registered the app twice, with two client identifiers and two secrets, only one
 * of which the developer would ever be shown.
 */

import { and, desc, eq } from "drizzle-orm";

import { createClient } from "./clients.js";
import { firstRow, requireRow } from "./rows.js";
import { nowValue } from "./time.js";
import { clientRequests } from "../schema/clients.js";

import type { ClientInput } from "./clients.js";
import type { Executor } from "./executor.js";
import type { EndpointScope } from "./scope.js";
import type {
  Client,
  ClientRequest,
  NewClientRequest,
} from "../schema/clients.js";
import type { SQL } from "drizzle-orm";

/** The caller-supplied half of a registration request. */
export type ClientRequestInput = Pick<
  NewClientRequest,
  "requestedByEmail" | "payload" | "trackingTokenHash"
>;

/** Files a registration request against the scoped endpoint. */
export async function createClientRequest(
  db: Executor,
  scope: EndpointScope,
  input: ClientRequestInput,
): Promise<ClientRequest> {
  const rows = await db
    .insert(clientRequests)
    .values({ ...input, endpointId: scope.endpointId })
    .returning();
  return requireRow(rows, "insert into client_requests");
}

/**
 * Lists the scoped endpoint's registration requests, newest first.
 *
 * @param db - The connection or transaction to use.
 * @param scope - The endpoint whose queue is being read.
 * @param status - Restricts to one review state; omit for all of them.
 */
export async function listClientRequests(
  db: Executor,
  scope: EndpointScope,
  status?: ClientRequest["status"],
): Promise<readonly ClientRequest[]> {
  const predicate =
    status === undefined
      ? eq(clientRequests.endpointId, scope.endpointId)
      : and(
          eq(clientRequests.endpointId, scope.endpointId),
          eq(clientRequests.status, status),
        );

  return await db
    .select()
    .from(clientRequests)
    .where(predicate)
    .orderBy(desc(clientRequests.createdAt));
}

/** Reads the one request a predicate selects, or undefined. */
async function selectClientRequest(
  db: Executor,
  predicate: SQL | undefined,
): Promise<ClientRequest | undefined> {
  const [row] = await db
    .select()
    .from(clientRequests)
    .where(predicate)
    .limit(1);
  return row;
}

/** Reads one of the scoped endpoint's registration requests. */
export async function getClientRequest(
  db: Executor,
  scope: EndpointScope,
  requestId: string,
): Promise<ClientRequest | undefined> {
  return await selectClientRequest(
    db,
    and(
      eq(clientRequests.endpointId, scope.endpointId),
      eq(clientRequests.id, requestId),
    ),
  );
}

/**
 * Reads a request by the token the developer was given for it.
 *
 * The developer portal is not an authenticated surface — somebody asking for a client has
 * no account yet — so this is how a submission is followed up: the identifier says which
 * request, and the token proves it is the one the caller filed. Both are required, and the
 * token is compared as a digest, so a leaked identifier alone reveals nothing.
 *
 * @param db - The connection or transaction to use.
 * @param scope - The endpoint the request was filed against.
 * @param requestId - The identifier from the submission response.
 * @param trackingTokenHash - SHA-256 of the token from the submission response.
 */
export async function findClientRequestByTrackingToken(
  db: Executor,
  scope: EndpointScope,
  requestId: string,
  trackingTokenHash: string,
): Promise<ClientRequest | undefined> {
  return await selectClientRequest(
    db,
    and(
      eq(clientRequests.endpointId, scope.endpointId),
      eq(clientRequests.id, requestId),
      eq(clientRequests.trackingTokenHash, trackingTokenHash),
    ),
  );
}

/** Why a decision could not be recorded. */
export type DecisionRefusal = "not-found" | "already-decided";

/** The outcome of approving a request. */
export type ApprovalResult =
  | {
      readonly ok: true;
      readonly request: ClientRequest;
      readonly client: Client;
    }
  | { readonly ok: false; readonly reason: DecisionRefusal };

/** The outcome of rejecting a request. */
export type RejectionResult =
  | { readonly ok: true; readonly request: ClientRequest }
  | { readonly ok: false; readonly reason: DecisionRefusal };

/** Who decided, and what they said about it. */
export interface DecisionInput {
  /** The deciding admin user, or null for an automated decision. */
  readonly reviewerId: string | null;
  readonly decisionNote?: string;
}

/**
 * Claims a pending request for a decision.
 *
 * Returns the claimed row, or undefined when the guard did not hold — which is
 * the same statement doing the deciding and the acting, so no two callers can
 * both claim it.
 */
async function claimRequest(
  tx: Executor,
  scope: EndpointScope,
  requestId: string,
  status: ClientRequest["status"],
  decision: DecisionInput,
  now?: Date,
): Promise<ClientRequest | undefined> {
  const rows = await tx
    .update(clientRequests)
    .set({
      status,
      reviewerId: decision.reviewerId,
      decisionNote: decision.decisionNote ?? null,
      decidedAt: nowValue(now),
    })
    .where(
      and(
        eq(clientRequests.id, requestId),
        eq(clientRequests.endpointId, scope.endpointId),
        eq(clientRequests.status, "pending"),
      ),
    )
    .returning();

  return firstRow(rows);
}

/**
 * Explains a failed claim.
 *
 * Only runs once the conditional update has already declined, so it decides
 * nothing; it exists so that the console can say "somebody else has already
 * reviewed this" rather than "not found", which would look like a bug.
 */
async function explainRefusal(
  tx: Executor,
  scope: EndpointScope,
  requestId: string,
): Promise<DecisionRefusal> {
  const existing = await getClientRequest(tx, scope, requestId);
  return existing === undefined ? "not-found" : "already-decided";
}

/**
 * Approves a request and registers the client it asked for.
 *
 * The client is created from `client`, not from the stored payload: an
 * administrator may narrow the requested scopes or correct a redirect URI before
 * approving, and the payload is retained verbatim so the difference between what
 * was asked for and what was granted stays visible.
 */
export async function approveClientRequest(
  db: Executor,
  scope: EndpointScope,
  requestId: string,
  decision: DecisionInput,
  client: ClientInput,
  now?: Date,
): Promise<ApprovalResult> {
  return await db.transaction(async (tx) => {
    const claimed = await claimRequest(
      tx,
      scope,
      requestId,
      "approved",
      decision,
      now,
    );
    if (claimed === undefined) {
      return { ok: false, reason: await explainRefusal(tx, scope, requestId) };
    }

    const created = await createClient(tx, scope, client);

    const linked = await tx
      .update(clientRequests)
      .set({ resultingClientId: created.id })
      .where(eq(clientRequests.id, claimed.id))
      .returning();

    return {
      ok: true,
      request: requireRow(linked, "link client_requests to client"),
      client: created,
    };
  });
}

/** Rejects a request, leaving the payload as the record of what was asked. */
export async function rejectClientRequest(
  db: Executor,
  scope: EndpointScope,
  requestId: string,
  decision: DecisionInput,
  now?: Date,
): Promise<RejectionResult> {
  return await db.transaction(async (tx) => {
    const claimed = await claimRequest(
      tx,
      scope,
      requestId,
      "rejected",
      decision,
      now,
    );
    if (claimed === undefined) {
      return { ok: false, reason: await explainRefusal(tx, scope, requestId) };
    }
    return { ok: true, request: claimed };
  });
}
