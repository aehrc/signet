/**
 * Personal access tokens for the admin API.
 *
 * {@link findLiveApiToken} is the other entry point at which a tenant scope comes
 * into existence - a PAT names its tenant, so presenting one both authenticates
 * the caller and fixes the tenant, and there is no way to present a token for one
 * tenant and act on another.
 *
 * A PAT carries a role of its own rather than inheriting the creator's. A script
 * that only reads the audit log should hold a `viewer` token even if the person
 * who minted it is an owner, and revoking that script's access should not mean
 * changing a human's membership.
 *
 * Author: John Grimes
 */

import { and, eq, gt, isNull, or, sql } from "drizzle-orm";

import { tenantIdForApiTokenDigest } from "./routines.js";
import { firstRow, requireRow } from "./rows.js";
import {
  executorFor,
  tenantScopeFromRow,
  withDeclaredTenant,
} from "./scope.js";
import { nowValue } from "./time.js";
import { apiTokens, tenants } from "../schema/tenancy.js";

import type { Executor } from "./executor.js";
import type { TenantRole } from "./roles.js";
import type { BoundTenantScope, TenantScope } from "./scope.js";
import type { ApiToken, NewApiToken } from "../schema/tenancy.js";

/** The caller-supplied half of a new personal access token. */
export type ApiTokenInput = Pick<
  NewApiToken,
  "name" | "tokenHash" | "role" | "createdBy" | "expiresAt"
>;

/** Mints a personal access token within the scoped tenant. */
export async function createApiToken(
  scope: BoundTenantScope,
  input: ApiTokenInput,
): Promise<ApiToken> {
  const rows = await executorFor(scope)
    .insert(apiTokens)
    .values({ ...input, tenantId: scope.tenantId })
    .returning();
  return requireRow(rows, "insert into api_tokens");
}

/** An authenticated API caller: which tenant, and with what authority. */
export interface AuthenticatedApiToken {
  readonly token: ApiToken;
  readonly scope: TenantScope;
  readonly role: TenantRole;
}

/**
 * Resolves a presented bearer token to a tenant scope.
 *
 * Not revoked, and not expired - a null `expires_at` means a token that does not
 * expire, which is why the predicate is a disjunction rather than a comparison
 * against a default. Both conditions are in SQL so that a caller cannot obtain
 * the row and then forget to check one of them.
 *
 * `last_used_at` is deliberately not updated here. This runs on every API
 * request, and turning an indexed read into a write would serialise concurrent
 * requests holding the same token behind a row lock; {@link touchApiToken} is
 * called separately, after the request has been authorised.
 *
 * Two steps, because the digest is all the request carries and `api_tokens` is
 * tenant-owned: the routine turns the digest into a tenant identifier, and the
 * liveness predicate is then evaluated inside a transaction declared for it. The
 * routine deliberately answers for a revoked or expired token as well as a live
 * one - it maps a digest to a tenant and judges nothing - so the conditions that
 * decide whether the token may be used are still in the one query below, where a
 * caller cannot obtain the row and forget to check them.
 *
 * @param db - The connection to resolve on. No tenant need be declared.
 * @param tokenHash - The presented token's digest, never the token.
 * @param now - The instant to compare the expiry against. Defaults to the
 *   database clock.
 * @returns The token, its tenant scope and its role, or undefined when no live
 *   token has that digest. The scope is unbound, for the reason
 *   `resolveTenantScope` gives.
 */
export async function findLiveApiToken(
  db: Executor,
  tokenHash: string,
  now?: Date,
): Promise<AuthenticatedApiToken | undefined> {
  const tenantId = await tenantIdForApiTokenDigest(db, tokenHash);
  if (tenantId === undefined) {
    return undefined;
  }

  return await withDeclaredTenant(db, tenantId, async (tx) => {
    const rows = await tx
      .select({ token: apiTokens, tenant: tenants })
      .from(apiTokens)
      .innerJoin(tenants, eq(tenants.id, apiTokens.tenantId))
      .where(
        and(
          eq(apiTokens.tokenHash, tokenHash),
          isNull(apiTokens.revokedAt),
          or(
            isNull(apiTokens.expiresAt),
            gt(apiTokens.expiresAt, nowValue(now)),
          ),
        ),
      )
      .limit(1);

    const row = firstRow(rows);
    return row === undefined
      ? undefined
      : {
          token: row.token,
          scope: tenantScopeFromRow(row.tenant),
          role: row.token.role,
        };
  });
}

/**
 * Records that a token was used, for the "last used" column in the console.
 *
 * Takes the scope {@link findLiveApiToken} resolved rather than a token
 * identifier alone, so the write cannot name a token belonging to another
 * tenant - the policy would refuse it, and now so does the compiler.
 */
export async function touchApiToken(
  scope: BoundTenantScope,
  tokenId: string,
  now?: Date,
): Promise<void> {
  await executorFor(scope)
    .update(apiTokens)
    .set({ lastUsedAt: nowValue(now) })
    .where(
      and(eq(apiTokens.id, tokenId), eq(apiTokens.tenantId, scope.tenantId)),
    );
}

/**
 * Lists the scoped tenant's tokens, newest first.
 *
 * The hash is part of the row and is returned; it is not a credential, and the
 * console needs the rest of the row. The token itself was shown once, at
 * creation, and cannot be recovered from here.
 */
export async function listApiTokens(
  scope: BoundTenantScope,
): Promise<readonly ApiToken[]> {
  return await executorFor(scope)
    .select()
    .from(apiTokens)
    .where(eq(apiTokens.tenantId, scope.tenantId))
    .orderBy(sql`${apiTokens.createdAt} desc`);
}

/**
 * Revokes one of the scoped tenant's tokens.
 *
 * @returns Whether a live token belonging to this tenant was revoked.
 */
export async function revokeApiToken(
  scope: BoundTenantScope,
  tokenId: string,
  now?: Date,
): Promise<boolean> {
  const rows = await executorFor(scope)
    .update(apiTokens)
    .set({ revokedAt: nowValue(now) })
    .where(
      and(
        eq(apiTokens.id, tokenId),
        eq(apiTokens.tenantId, scope.tenantId),
        isNull(apiTokens.revokedAt),
      ),
    )
    .returning({ id: apiTokens.id });
  return rows.length > 0;
}
