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

import { firstRow, requireRow } from "./rows.js";
import { tenantScopeFromRow } from "./scope.js";
import { nowValue } from "./time.js";
import { apiTokens, tenants } from "../schema/tenancy.js";

import type { Executor } from "./executor.js";
import type { TenantRole } from "./roles.js";
import type { TenantScope } from "./scope.js";
import type { ApiToken, NewApiToken } from "../schema/tenancy.js";

/** The caller-supplied half of a new personal access token. */
export type ApiTokenInput = Pick<
  NewApiToken,
  "name" | "tokenHash" | "role" | "createdBy" | "expiresAt"
>;

/** Mints a personal access token within the scoped tenant. */
export async function createApiToken(
  db: Executor,
  scope: TenantScope,
  input: ApiTokenInput,
): Promise<ApiToken> {
  const rows = await db
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
 */
export async function findLiveApiToken(
  db: Executor,
  tokenHash: string,
  now?: Date,
): Promise<AuthenticatedApiToken | undefined> {
  const rows = await db
    .select({ token: apiTokens, tenant: tenants })
    .from(apiTokens)
    .innerJoin(tenants, eq(tenants.id, apiTokens.tenantId))
    .where(
      and(
        eq(apiTokens.tokenHash, tokenHash),
        isNull(apiTokens.revokedAt),
        or(isNull(apiTokens.expiresAt), gt(apiTokens.expiresAt, nowValue(now))),
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
}

/** Records that a token was used, for the "last used" column in the console. */
export async function touchApiToken(
  db: Executor,
  tokenId: string,
  now?: Date,
): Promise<void> {
  await db
    .update(apiTokens)
    .set({ lastUsedAt: nowValue(now) })
    .where(eq(apiTokens.id, tokenId));
}

/**
 * Lists the scoped tenant's tokens, newest first.
 *
 * The hash is part of the row and is returned; it is not a credential, and the
 * console needs the rest of the row. The token itself was shown once, at
 * creation, and cannot be recovered from here.
 */
export async function listApiTokens(
  db: Executor,
  scope: TenantScope,
): Promise<readonly ApiToken[]> {
  return await db
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
  db: Executor,
  scope: TenantScope,
  tokenId: string,
  now?: Date,
): Promise<boolean> {
  const rows = await db
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
