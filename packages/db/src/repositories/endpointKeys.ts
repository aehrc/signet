/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Endpoint signing keys and their rotation.
 *
 * Three states, and the order they move in matters: a key is published as `next`
 * so that relying parties have fetched it before it signs anything, then promoted
 * to `active`, then `retired` once the tokens it signed have expired. Promotion is
 * therefore not "set this key active" - it is a swap, and it happens in one
 * transaction so that there is never an instant with two active keys or none.
 * That transaction is now the caller's: the bound scope carries it, so the three
 * statements below share the atomicity boundary the declaration opened rather than
 * a nested one of their own.
 *
 * No function here returns a private key in a form any API could serve: the
 * column holds an AES-256-GCM envelope, and decrypting it is the caller's
 * business, immediately before signing.
 *
 * Author: John Grimes
 */

import { and, asc, desc, eq, inArray, sql } from "drizzle-orm";

import { firstRow, requireRow } from "./rows.js";
import { executorFor } from "./scope.js";
import { nowValue } from "./time.js";
import { endpointKeys } from "../schema/endpoints.js";

import type { BoundEndpointScope } from "./scope.js";
import type { EndpointKey, NewEndpointKey } from "../schema/endpoints.js";

/** The caller-supplied half of a signing key. */
export type EndpointKeyInput = Omit<
  NewEndpointKey,
  "id" | "endpointId" | "createdAt" | "activatedAt" | "retiredAt"
>;

/**
 * Adds a key to the scoped endpoint.
 *
 * Defaults to `next`, per the column default: a key that appears and immediately
 * signs is a key nobody has cached, and every relying party caching the JWKS
 * would reject the first tokens it produced.
 */
export async function insertEndpointKey(
  scope: BoundEndpointScope,
  input: EndpointKeyInput,
): Promise<EndpointKey> {
  const rows = await executorFor(scope)
    .insert(endpointKeys)
    .values({ ...input, endpointId: scope.endpointId })
    .returning();
  return requireRow(rows, "insert into endpoint_keys");
}

/** Lists every key of the scoped endpoint, newest first. */
export async function listEndpointKeys(
  scope: BoundEndpointScope,
): Promise<readonly EndpointKey[]> {
  return await executorFor(scope)
    .select()
    .from(endpointKeys)
    .where(eq(endpointKeys.endpointId, scope.endpointId))
    .orderBy(desc(endpointKeys.createdAt));
}

/**
 * The key to sign with.
 *
 * Ordered by activation time and limited to one. The schema does not constrain an
 * endpoint to a single active key - a partial unique index would have made the
 * promotion transaction below deadlock-prone - so this query decides, rather than
 * assuming, which of them wins: the most recently activated.
 */
export async function getActiveEndpointKey(
  scope: BoundEndpointScope,
): Promise<EndpointKey | undefined> {
  const rows = await executorFor(scope)
    .select()
    .from(endpointKeys)
    .where(
      and(
        eq(endpointKeys.endpointId, scope.endpointId),
        eq(endpointKeys.status, "active"),
      ),
    )
    .orderBy(desc(endpointKeys.activatedAt))
    .limit(1);
  return firstRow(rows);
}

/**
 * The keys the endpoint's JWKS publishes: active and next.
 *
 * Retired keys are excluded. A relying party that has cached the JWKS will
 * continue to verify tokens signed by a retired key until its cache expires,
 * which is exactly why retirement is a state and not a delete - but the document
 * should stop advertising a key the moment Signet stops signing with it.
 */
export async function listPublishableEndpointKeys(
  scope: BoundEndpointScope,
): Promise<readonly EndpointKey[]> {
  return await executorFor(scope)
    .select()
    .from(endpointKeys)
    .where(
      and(
        eq(endpointKeys.endpointId, scope.endpointId),
        inArray(endpointKeys.status, ["active", "next"]),
      ),
    )
    .orderBy(asc(endpointKeys.status), asc(endpointKeys.kid));
}

/** Reads one of the scoped endpoint's keys by `kid`. */
export async function getEndpointKeyByKid(
  scope: BoundEndpointScope,
  kid: string,
): Promise<EndpointKey | undefined> {
  const [row] = await executorFor(scope)
    .select()
    .from(endpointKeys)
    .where(
      and(
        eq(endpointKeys.endpointId, scope.endpointId),
        eq(endpointKeys.kid, kid),
      ),
    )
    .limit(1);
  return row;
}

/** The outcome of a rotation. */
export type KeyPromotion =
  | {
      readonly ok: true;
      readonly activated: EndpointKey;
      readonly retired: readonly EndpointKey[];
    }
  | { readonly ok: false; readonly reason: "no-next-key" };

/**
 * Promotes the endpoint's `next` key to `active` and retires the outgoing one.
 *
 * In one transaction, and in this order: find the incoming key, retire every
 * currently active key, then activate the incoming one. Doing it the other way
 * round would leave a window in which two keys are active and
 * {@link getActiveEndpointKey} could return either.
 *
 * Nothing is retired when there is no `next` key. Rotating to nothing would
 * leave the endpoint unable to sign, which is a worse outcome than refusing.
 *
 * If several keys are `next` - an operator can generate more than one - the
 * oldest is promoted, so that repeated rotation drains the queue in the order it
 * was filled.
 */
export async function promoteNextEndpointKey(
  scope: BoundEndpointScope,
  now?: Date,
): Promise<KeyPromotion> {
  const candidates = await executorFor(scope)
    .select()
    .from(endpointKeys)
    .where(
      and(
        eq(endpointKeys.endpointId, scope.endpointId),
        eq(endpointKeys.status, "next"),
      ),
    )
    .orderBy(asc(endpointKeys.createdAt))
    .limit(1)
    .for("update");

  const incoming = firstRow(candidates);
  if (incoming === undefined) {
    return { ok: false, reason: "no-next-key" };
  }

  const retired = await executorFor(scope)
    .update(endpointKeys)
    .set({ status: "retired", retiredAt: nowValue(now) })
    .where(
      and(
        eq(endpointKeys.endpointId, scope.endpointId),
        eq(endpointKeys.status, "active"),
      ),
    )
    .returning();

  const activatedRows = await executorFor(scope)
    .update(endpointKeys)
    .set({ status: "active", activatedAt: nowValue(now) })
    .where(eq(endpointKeys.id, incoming.id))
    .returning();

  return {
    ok: true,
    activated: requireRow(activatedRows, "activate endpoint_keys row"),
    retired,
  };
}

/**
 * Retires one key without promoting anything.
 *
 * Used to withdraw a key that must stop signing immediately - a suspected
 * compromise - accepting that the endpoint cannot issue tokens until another key
 * is activated. That is the correct trade: a compromised key must not sign, and a
 * brief outage is recoverable where a leaked signing key is not.
 */
export async function retireEndpointKey(
  scope: BoundEndpointScope,
  kid: string,
  now?: Date,
): Promise<EndpointKey | undefined> {
  const [row] = await executorFor(scope)
    .update(endpointKeys)
    .set({ status: "retired", retiredAt: nowValue(now) })
    .where(
      and(
        eq(endpointKeys.endpointId, scope.endpointId),
        eq(endpointKeys.kid, kid),
      ),
    )
    .returning();
  return row;
}

/**
 * Deletes retired keys that were retired before a cut-off.
 *
 * Retention has to outlast the longest-lived token the key signed, or a token
 * still within its validity period becomes unverifiable to a relying party that
 * refetches the JWKS. The cut-off is the caller's to choose, from the endpoint's
 * own access token TTL.
 *
 * @returns How many keys were deleted.
 */
export async function deleteRetiredEndpointKeys(
  scope: BoundEndpointScope,
  retiredBefore: Date,
): Promise<number> {
  const rows = await executorFor(scope)
    .delete(endpointKeys)
    .where(
      and(
        eq(endpointKeys.endpointId, scope.endpointId),
        eq(endpointKeys.status, "retired"),
        sql`${endpointKeys.retiredAt} < ${retiredBefore}`,
      ),
    )
    .returning({ id: endpointKeys.id });
  return rows.length;
}
