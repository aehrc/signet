/**
 * Registered SMART apps.
 *
 * `clients.client_id` is globally unique, so a lookup by it *must* carry an
 * endpoint predicate or it would happily return another tenant's client. Every
 * read here does, and the OAuth path goes through `resolveClientScope`, which
 * re-checks ownership when it builds the scope. A client identifier is
 * attacker-supplied on every token request; this is the single most likely place
 * in the schema for a cross-tenant leak, which is why it is guarded twice.
 *
 * Author: John Grimes
 */

import { and, asc, eq } from "drizzle-orm";

import { requireRow } from "./rows.js";
import { clientScopeFromRow, executorFor } from "./scope.js";
import { nowValue } from "./time.js";
import { clients } from "../schema/clients.js";

import type { BoundClientScope, BoundEndpointScope } from "./scope.js";
import type { Client, NewClient } from "../schema/clients.js";
import type { SQL } from "drizzle-orm";

/** The caller-supplied half of a client registration. */
export type ClientInput = Omit<
  NewClient,
  "id" | "endpointId" | "createdAt" | "updatedAt"
>;

/**
 * What a client's credentials may be replaced with.
 *
 * Narrower than {@link ClientInput} on purpose: rotating a secret and editing a
 * display name are different operations with different audit events, and a patch
 * type that could do both would let one be mistaken for the other.
 */
export type ClientCredentialPatch = Pick<
  ClientInput,
  "secretHash" | "secretExpiresAt" | "jwks" | "jwksUri"
>;

/** Registers a client on the scoped endpoint. */
export async function createClient(
  scope: BoundEndpointScope,
  input: ClientInput,
): Promise<Client> {
  const rows = await executorFor(scope)
    .insert(clients)
    .values({ ...input, endpointId: scope.endpointId })
    .returning();
  return requireRow(rows, "insert into clients");
}

/** Lists the scoped endpoint's clients, by name. */
export async function listClients(
  scope: BoundEndpointScope,
): Promise<readonly Client[]> {
  return await executorFor(scope)
    .select()
    .from(clients)
    .where(eq(clients.endpointId, scope.endpointId))
    .orderBy(asc(clients.name));
}

/**
 * Reads the one client a predicate selects within the scoped endpoint.
 *
 * Written once, and the endpoint predicate is why: `clients.client_id` is unique
 * across the deployment, so a lookup by it that lost the endpoint predicate would
 * return another tenant's client rather than nothing.
 */
async function selectClient(
  scope: BoundEndpointScope,
  identifies: SQL | undefined,
): Promise<Client | undefined> {
  const [row] = await executorFor(scope)
    .select()
    .from(clients)
    .where(and(eq(clients.endpointId, scope.endpointId), identifies))
    .limit(1);
  return row;
}

/** Reads one of the scoped endpoint's clients by surrogate identifier. */
export async function getClient(
  scope: BoundEndpointScope,
  id: string,
): Promise<Client | undefined> {
  return await selectClient(scope, eq(clients.id, id));
}

/**
 * Reads one of the scoped endpoint's clients by its OAuth `client_id`.
 *
 * See the module header for why the endpoint predicate is not optional here.
 */
export async function getClientByClientId(
  scope: BoundEndpointScope,
  clientId: string,
): Promise<Client | undefined> {
  return await selectClient(scope, eq(clients.clientId, clientId));
}

/** A client resolved by its OAuth identifier, with its scope. */
export interface ResolvedClient {
  readonly scope: BoundClientScope;
  readonly client: Client;
}

/**
 * Resolves the `client_id` presented at `/authorize` or `/token`.
 *
 * The endpoint predicate {@link getClientByClientId} applies is re-checked by
 * {@link clientScopeFromRow}: a client identifier registered on another endpoint
 * must read as unknown here, not as a client that then fails a later check - the
 * two are different error responses and different audit events.
 *
 * The client's status is deliberately not filtered. A suspended client presenting a
 * valid secret must be told it is suspended, and that decision is the grant
 * handler's to make and audit.
 *
 * @param scope - The endpoint the client must belong to, bound to the transaction
 *   that declared its tenant.
 * @param clientId - The OAuth `client_id` the caller presented.
 * @returns The client and a scope narrowed to it, or undefined when the endpoint
 *   has no such client.
 */
export async function resolveClientScope(
  scope: BoundEndpointScope,
  clientId: string,
): Promise<ResolvedClient | undefined> {
  const client = await getClientByClientId(scope, clientId);
  return client === undefined
    ? undefined
    : { scope: clientScopeFromRow(scope, client), client };
}

/** Reads the client the scope refers to. */
export async function getScopedClient(
  scope: BoundClientScope,
): Promise<Client | undefined> {
  return await getClient(scope, scope.clientRowId);
}

/** Applies a patch to the scoped client's registration. */
export async function updateClient(
  scope: BoundClientScope,
  patch: Partial<Omit<ClientInput, "clientId">>,
  now?: Date,
): Promise<Client | undefined> {
  const [row] = await executorFor(scope)
    .update(clients)
    .set({ ...patch, updatedAt: nowValue(now) })
    .where(
      and(
        eq(clients.id, scope.clientRowId),
        eq(clients.endpointId, scope.endpointId),
      ),
    )
    .returning();
  return row;
}

/**
 * Moves a client between registration states.
 *
 * Suspension is the reversible answer to a misbehaving app, and deletion is not
 * required to stop one: `pending`, `suspended` and `rejected` all fail
 * authentication, while the client's tokens and audit history survive.
 */
export async function setClientStatus(
  scope: BoundClientScope,
  status: Client["status"],
  now?: Date,
): Promise<Client | undefined> {
  return await updateClient(scope, { status }, now);
}

/**
 * Replaces the scoped client's credentials.
 *
 * Rotation, not recovery. The previous secret hash is overwritten and cannot be
 * recovered from anywhere, which is the intended consequence of storing a hash:
 * an operator who has lost a client secret issues a new one.
 */
export async function setClientCredentials(
  scope: BoundClientScope,
  patch: ClientCredentialPatch,
  now?: Date,
): Promise<Client | undefined> {
  return await updateClient(scope, patch, now);
}

/**
 * Records that the client's remote JWKS was fetched.
 *
 * Only the timestamp is stored, not the document. A cached JWKS that outlived the
 * client's own rotation would let a withdrawn key keep authenticating; the fetch
 * is cheap and the correctness is not negotiable, so the cache is a rate limiter
 * rather than a store.
 */
export async function recordClientJwksFetch(
  scope: BoundClientScope,
  now?: Date,
): Promise<void> {
  await executorFor(scope)
    .update(clients)
    .set({ jwksCachedAt: nowValue(now) })
    .where(
      and(
        eq(clients.id, scope.clientRowId),
        eq(clients.endpointId, scope.endpointId),
      ),
    );
}

/**
 * Deletes the scoped client.
 *
 * Everything issued to it - codes, tokens, consents, `jti` ledger entries -
 * cascades away, which is the point: a deleted client's refresh tokens must stop
 * working. Its audit events survive, because `audit_events` does not reference
 * the client row.
 *
 * @returns Whether a client was deleted.
 */
export async function deleteClient(scope: BoundClientScope): Promise<boolean> {
  const rows = await executorFor(scope)
    .delete(clients)
    .where(
      and(
        eq(clients.id, scope.clientRowId),
        eq(clients.endpointId, scope.endpointId),
      ),
    )
    .returning({ id: clients.id });
  return rows.length > 0;
}
