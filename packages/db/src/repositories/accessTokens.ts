/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Metadata for issued access tokens.
 *
 * The token itself is a signed JWT and needs nothing from the database to be
 * verified. These rows exist so that introspection can answer for a token, and so
 * that revocation is possible at all - a stateless token is otherwise valid until
 * it expires, whatever anyone decides in the meantime.
 *
 * That makes the rows a revocation list, not a cache: deleting one before the
 * token expires would silently un-revoke it, because a resource server that
 * validates the signature and finds no row has no reason to refuse. The sweep here
 * therefore removes only rows whose tokens have already expired.
 *
 * Author: John Grimes
 */

import { and, desc, eq, isNull, lte } from "drizzle-orm";

import { toIntrospectableToken } from "./mappers.js";
import { firstRow, requireRow } from "./rows.js";
import { executorFor } from "./scope.js";
import { nowValue } from "./time.js";
import { clients } from "../schema/clients.js";
import { accessTokens } from "../schema/runtime.js";

import type { Executor } from "./executor.js";
import type {
  BoundClientScope,
  BoundEndpointScope,
  BoundTenantScope,
} from "./scope.js";
import type { AccessToken, NewAccessToken } from "../schema/runtime.js";
import type { IntrospectableToken } from "@signet/core";
import type { SQL } from "drizzle-orm";

/**
 * The caller-supplied half of an access token record.
 *
 * Named `...RecordInput` rather than `AccessTokenInput`, which `@signet/core`
 * already uses for the claim-assembly input. A server module importing both would
 * otherwise have to alias one of them, and the two are easy to confuse: one
 * describes a row, the other describes a token payload.
 *
 * `issuer` and `audience` are required rather than derived from the endpoint, and
 * that is deliberate: the endpoint's FHIR base URL can be edited, and a token must
 * introspect as it was minted. Recomputing them at introspection time would
 * quietly rewrite history.
 */
export type AccessTokenRecordInput = Omit<
  NewAccessToken,
  "endpointId" | "clientId" | "issuedAt" | "revokedAt"
>;

/** Records an issued access token against the scoped client. */
export async function recordAccessToken(
  scope: BoundClientScope,
  input: AccessTokenRecordInput,
): Promise<AccessToken> {
  const rows = await executorFor(scope)
    .insert(accessTokens)
    .values({
      ...input,
      endpointId: scope.endpointId,
      clientId: scope.clientRowId,
    })
    .returning();
  return requireRow(rows, "insert into access_tokens");
}

/** Reads one of the scoped endpoint's token records by `jti`. */
export async function findAccessToken(
  scope: BoundEndpointScope,
  jti: string,
): Promise<AccessToken | undefined> {
  const [row] = await executorFor(scope)
    .select()
    .from(accessTokens)
    .where(
      and(
        eq(accessTokens.jti, jti),
        eq(accessTokens.endpointId, scope.endpointId),
      ),
    )
    .limit(1);
  return row;
}

/**
 * Reads a token record in the shape introspection consumes.
 *
 * Revoked and expired tokens are returned, not filtered out. Introspection has to
 * answer `active: false` for them, and `@signet/core` makes that judgement from
 * the timestamps this carries - one place, one clock. Filtering here would make an
 * expired token indistinguishable from a forged `jti`, which is a distinction the
 * audit log wants.
 *
 * @returns Undefined only when no such token was ever issued on this endpoint.
 */
export async function introspectAccessToken(
  scope: BoundEndpointScope,
  jti: string,
): Promise<IntrospectableToken | undefined> {
  const rows = await executorFor(scope)
    .select({ token: accessTokens, clientId: clients.clientId })
    .from(accessTokens)
    .innerJoin(clients, eq(clients.id, accessTokens.clientId))
    .where(
      and(
        eq(accessTokens.jti, jti),
        eq(accessTokens.endpointId, scope.endpointId),
      ),
    )
    .limit(1);

  const row = firstRow(rows);
  return row === undefined
    ? undefined
    : toIntrospectableToken(row.token, row.clientId);
}

/**
 * Revokes one token.
 *
 * @returns Whether a live token was revoked, so that RFC 7009's "revoke is
 *   idempotent" response can be given without pretending something happened.
 */
export async function revokeAccessToken(
  scope: BoundEndpointScope,
  jti: string,
  now?: Date,
): Promise<boolean> {
  const rows = await executorFor(scope)
    .update(accessTokens)
    .set({ revokedAt: nowValue(now) })
    .where(
      and(
        eq(accessTokens.jti, jti),
        eq(accessTokens.endpointId, scope.endpointId),
        isNull(accessTokens.revokedAt),
      ),
    )
    .returning({ jti: accessTokens.jti });
  return rows.length > 0;
}

/**
 * Revokes every live token issued to the scoped client.
 *
 * Used when a client is suspended or deleted, and by the end user's management
 * page.
 *
 * @returns How many tokens were revoked.
 */
export async function revokeAccessTokensForClient(
  scope: BoundClientScope,
  now?: Date,
): Promise<number> {
  const rows = await executorFor(scope)
    .update(accessTokens)
    .set({ revokedAt: nowValue(now) })
    .where(
      and(
        eq(accessTokens.clientId, scope.clientRowId),
        eq(accessTokens.endpointId, scope.endpointId),
        isNull(accessTokens.revokedAt),
      ),
    )
    .returning({ jti: accessTokens.jti });
  return rows.length;
}

/**
 * Revokes the live tokens a predicate selects.
 *
 * The two public revocations below differ only in whether they name a client, and the
 * statement is the security-relevant part: a copy that forgot `isNull(revokedAt)` would
 * silently restamp an already-revoked row and report it as newly revoked.
 */
async function revokeMatchingAccessTokens(
  scope: BoundTenantScope,
  predicate: SQL | undefined,
  now?: Date,
): Promise<number> {
  const rows = await executorFor(scope)
    .update(accessTokens)
    .set({ revokedAt: nowValue(now) })
    .where(and(predicate, isNull(accessTokens.revokedAt)))
    .returning({ jti: accessTokens.jti });
  return rows.length;
}

/**
 * Revokes every live token issued for one subject on the scoped endpoint.
 *
 * The subject is an end user identifier, or a client identifier for a backend service.
 * This is "sign this person out of everything".
 *
 * @returns How many tokens were revoked.
 */
export async function revokeAccessTokensForSubject(
  scope: BoundEndpointScope,
  subject: string,
  now?: Date,
): Promise<number> {
  return await revokeMatchingAccessTokens(
    scope,
    and(
      eq(accessTokens.subject, subject),
      eq(accessTokens.endpointId, scope.endpointId),
    ),
    now,
  );
}

/**
 * Revokes one subject's live tokens for one client.
 *
 * Narrower than {@link revokeAccessTokensForSubject}, and the difference matters: this is
 * the management page's "disconnect this app", where revoking every token the person
 * holds would disconnect apps they did not ask to disconnect.
 *
 * @returns How many tokens were revoked.
 */
export async function revokeAccessTokensForSubjectAndClient(
  scope: BoundClientScope,
  subject: string,
  now?: Date,
): Promise<number> {
  return await revokeMatchingAccessTokens(
    scope,
    and(
      eq(accessTokens.subject, subject),
      eq(accessTokens.endpointId, scope.endpointId),
      eq(accessTokens.clientId, scope.clientRowId),
    ),
    now,
  );
}

/** Lists a subject's token records on the scoped endpoint, newest first. */
export async function listAccessTokensForSubject(
  scope: BoundEndpointScope,
  subject: string,
): Promise<readonly AccessToken[]> {
  return await executorFor(scope)
    .select()
    .from(accessTokens)
    .where(
      and(
        eq(accessTokens.subject, subject),
        eq(accessTokens.endpointId, scope.endpointId),
      ),
    )
    .orderBy(desc(accessTokens.issuedAt));
}

/**
 * Deletes records for tokens that have already expired.
 *
 * Part of the cross-tenant expiry sweep, so it takes a connection rather than a
 * bound scope and needs the owning identity; see `./unscoped.ts`.
 *
 * @param db - The connection to delete on, which must be the owning identity.
 * @param before - Delete records whose token expired before this instant. A
 *   caller may pass an earlier time than "now" to keep a grace period, so that
 *   introspecting a just-expired token still reports `active: false` with its
 *   metadata rather than as an unknown token.
 * @returns How many rows were deleted.
 */
export async function deleteExpiredAccessTokens(
  db: Executor,
  before?: Date,
): Promise<number> {
  const rows = await db
    .delete(accessTokens)
    .where(lte(accessTokens.expiresAt, nowValue(before)))
    .returning({ jti: accessTokens.jti });
  return rows.length;
}
