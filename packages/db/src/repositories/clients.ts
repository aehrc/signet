/**
 * Registered SMART apps.
 *
 * `clients.client_id` is globally unique, so a lookup by it *must* carry an
 * endpoint predicate or it would happily return another tenant's client. Every
 * read here does, and the OAuth path goes through `resolveClientScope`, which
 * re-checks ownership when it builds the scope. A client identifier is
 * attacker-supplied on every token request; this is the single most likely place
 * in the schema for a cross-tenant leak, which is why it is guarded twice.
 */

import { and, asc, eq } from "drizzle-orm";

import { requireRow } from "./rows.js";
import { nowValue } from "./time.js";
import { clients } from "../schema/clients.js";

import type { Executor } from "./executor.js";
import type { ClientScope, EndpointScope } from "./scope.js";
import type { Client, NewClient } from "../schema/clients.js";

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
  db: Executor,
  scope: EndpointScope,
  input: ClientInput,
): Promise<Client> {
  const rows = await db
    .insert(clients)
    .values({ ...input, endpointId: scope.endpointId })
    .returning();
  return requireRow(rows, "insert into clients");
}

/** Lists the scoped endpoint's clients, by name. */
export async function listClients(
  db: Executor,
  scope: EndpointScope,
): Promise<readonly Client[]> {
  return await db
    .select()
    .from(clients)
    .where(eq(clients.endpointId, scope.endpointId))
    .orderBy(asc(clients.name));
}

/** Reads one of the scoped endpoint's clients by surrogate identifier. */
export async function getClient(
  db: Executor,
  scope: EndpointScope,
  id: string,
): Promise<Client | undefined> {
  const [row] = await db
    .select()
    .from(clients)
    .where(and(eq(clients.endpointId, scope.endpointId), eq(clients.id, id)))
    .limit(1);
  return row;
}

/**
 * Reads one of the scoped endpoint's clients by its OAuth `client_id`.
 *
 * See the module header for why the endpoint predicate is not optional here.
 */
export async function getClientByClientId(
  db: Executor,
  scope: EndpointScope,
  clientId: string,
): Promise<Client | undefined> {
  const [row] = await db
    .select()
    .from(clients)
    .where(
      and(
        eq(clients.endpointId, scope.endpointId),
        eq(clients.clientId, clientId),
      ),
    )
    .limit(1);
  return row;
}

/** Reads the client the scope refers to. */
export async function getScopedClient(
  db: Executor,
  scope: ClientScope,
): Promise<Client | undefined> {
  return await getClient(db, scope, scope.clientRowId);
}

/** Applies a patch to the scoped client's registration. */
export async function updateClient(
  db: Executor,
  scope: ClientScope,
  patch: Partial<Omit<ClientInput, "clientId">>,
  now?: Date,
): Promise<Client | undefined> {
  const [row] = await db
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
  db: Executor,
  scope: ClientScope,
  status: Client["status"],
  now?: Date,
): Promise<Client | undefined> {
  return await updateClient(db, scope, { status }, now);
}

/**
 * Replaces the scoped client's credentials.
 *
 * Rotation, not recovery. The previous secret hash is overwritten and cannot be
 * recovered from anywhere, which is the intended consequence of storing a hash:
 * an operator who has lost a client secret issues a new one.
 */
export async function setClientCredentials(
  db: Executor,
  scope: ClientScope,
  patch: ClientCredentialPatch,
  now?: Date,
): Promise<Client | undefined> {
  return await updateClient(db, scope, patch, now);
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
  db: Executor,
  scope: ClientScope,
  now?: Date,
): Promise<void> {
  await db
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
 * Everything issued to it — codes, tokens, consents, `jti` ledger entries —
 * cascades away, which is the point: a deleted client's refresh tokens must stop
 * working. Its audit events survive, because `audit_events` does not reference
 * the client row.
 *
 * @returns Whether a client was deleted.
 */
export async function deleteClient(
  db: Executor,
  scope: ClientScope,
): Promise<boolean> {
  const rows = await db
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
