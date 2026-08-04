/**
 * Tenant settings, membership and personal access tokens.
 *
 * Two invariants here are enforced by the data layer rather than by these handlers,
 * and are worth naming because the handlers look incomplete without them.
 *
 * A tenant can never be left with no owner. Demoting or removing its last one would
 * make it permanently unadministrable - nobody could grant membership to anybody -
 * so `setTenantMemberRole` and `removeTenantMember` refuse, under a row lock, and
 * these handlers translate the refusal into a 409.
 *
 * A personal access token carries its own role rather than inheriting the creator's.
 * That is what lets an owner mint a viewer token for a reporting script, and it is
 * why the create route refuses to mint a token more powerful than the caller: a
 * developer able to mint an owner token would be able to promote themselves.
 *
 * Author: John Grimes
 */

import {
  apiTokenCreateSchema,
  memberRoleSchema,
  tenantPatchSchema,
} from "@signet/contracts";
import {
  createApiToken,
  findAdminUserByEmail,
  generateOpaqueToken,
  getTenant,
  hashToken,
  listApiTokens,
  listTenantMembers,
  removeTenantMember,
  revokeApiToken,
  roleAtLeast,
  setTenantMemberRole,
  updateTenant,
  withTenantScope,
} from "@signet/db";

import { recordAdminEvent } from "./auditTrail.js";
import { requireRole } from "./authentication.js";
import { adminErrorBody, statusForAdminError } from "./errors.js";
import { TENANT_PATH } from "./paths.js";
import { principalAdminUserId } from "./principal.js";
import { parseBody } from "./requestBody.js";
import { apiTokenView, memberView } from "./views.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { Hono } from "hono";

/**
 * Registers the tenant-level routes.
 *
 * @param router - The admin API router.
 * @param context - The server's dependencies.
 */
export function registerTenantRoutes(
  router: Hono<SignetEnvironment>,
  context: ServerContext,
): void {
  /**
   * Renames the tenant.
   *
   * The slug is deliberately not editable. It is part of every endpoint issuer
   * under the tenant, so changing it would invalidate the `iss` of every token
   * already issued and every app's configuration. A tenant that needs a different
   * slug needs a new tenant.
   */
  router.patch(TENANT_PATH, requireRole("admin"), async (c) => {
    const { scope } = c.get("tenant");
    const body = await parseBody(c, tenantPatchSchema);
    if (body instanceof Response) {
      return body;
    }

    // Only the fields actually supplied are written, so a patch naming nothing
    // leaves the row alone rather than blanking the columns it did not mention.
    const patch = Object.fromEntries(
      Object.entries(body).filter(([, value]) => value !== undefined),
    );
    const updated = await withTenantScope(context.db, scope, (bound) =>
      updateTenant(bound, patch, context.clock()),
    );
    if (updated === undefined) {
      return c.json(
        adminErrorBody("not_found", "No such tenant"),
        statusForAdminError("not_found"),
      );
    }

    await recordAdminEvent(context, c, {
      action: "tenant.updated",
      target: { type: "tenant", id: scope.tenantId },
      detail: { fields: Object.keys(patch) },
    });

    return c.json({ tenant: { slug: updated.slug, name: updated.name } });
  });

  /** Lists the tenant's members. */
  router.get(`${TENANT_PATH}/members`, requireRole("viewer"), async (c) => {
    const { scope } = c.get("tenant");
    const members = await withTenantScope(context.db, scope, (bound) =>
      listTenantMembers(bound),
    );
    return c.json({
      members: members.map((row) => memberView(row.member, row.user)),
    });
  });

  /**
   * Grants or changes a membership, addressed by email.
   *
   * By email rather than by identifier because that is what an administrator knows
   * about a colleague. A person with no console account cannot be added: an
   * invitation flow that created an account from an email address would let a
   * tenant admin mint identities on a shared deployment.
   */
  router.put(`${TENANT_PATH}/members`, requireRole("admin"), async (c) => {
    const { scope, role } = c.get("tenant");
    const body = await parseBody(c, memberRoleSchema);
    if (body instanceof Response) {
      return body;
    }

    if (!roleAtLeast(role, body.role)) {
      return c.json(
        adminErrorBody(
          "forbidden",
          `You cannot grant ${body.role}, which is above your own ${role}`,
        ),
        statusForAdminError("forbidden"),
      );
    }

    const user = await findAdminUserByEmail(context.db, body.email);
    if (user === undefined) {
      return c.json(
        adminErrorBody(
          "not_found",
          "That email address has no console account on this deployment",
        ),
        statusForAdminError("not_found"),
      );
    }

    const change = await withTenantScope(context.db, scope, (bound) =>
      setTenantMemberRole(bound, user.id, body.role),
    );
    if (!change.ok) {
      return c.json(
        adminErrorBody(
          "conflict",
          "That change would leave the tenant with no owner",
        ),
        statusForAdminError("conflict"),
      );
    }

    await recordAdminEvent(context, c, {
      action: "tenant-member.role-changed",
      target: { type: "tenant-member", id: user.id },
      detail: { email: user.email, role: body.role },
    });

    return c.json({ member: memberView(change.value, user) });
  });

  /** Removes a membership. */
  router.delete(
    `${TENANT_PATH}/members/:adminUserId`,
    requireRole("admin"),
    async (c) => {
      const { scope } = c.get("tenant");
      const adminUserId = c.req.param("adminUserId");

      const change = await withTenantScope(context.db, scope, (bound) =>
        removeTenantMember(bound, adminUserId),
      );
      if (!change.ok) {
        return change.reason === "not-a-member"
          ? c.json(
              adminErrorBody("not_found", "That person is not a member"),
              statusForAdminError("not_found"),
            )
          : c.json(
              adminErrorBody(
                "conflict",
                "Removing the last owner would leave the tenant unadministrable",
              ),
              statusForAdminError("conflict"),
            );
      }

      await recordAdminEvent(context, c, {
        action: "tenant-member.removed",
        target: { type: "tenant-member", id: adminUserId },
      });

      return c.body(null, 204);
    },
  );

  /** Lists the tenant's personal access tokens. */
  router.get(`${TENANT_PATH}/api-tokens`, requireRole("admin"), async (c) => {
    const { scope } = c.get("tenant");
    const tokens = await listApiTokens(context.db, scope);
    return c.json({ tokens: tokens.map(apiTokenView) });
  });

  /**
   * Mints a personal access token.
   *
   * The token is in the response and nowhere else. It is stored as a SHA-256
   * digest, so this response is the only opportunity to copy it, and the console
   * says so.
   */
  router.post(`${TENANT_PATH}/api-tokens`, requireRole("admin"), async (c) => {
    const { scope, role } = c.get("tenant");
    const body = await parseBody(c, apiTokenCreateSchema);
    if (body instanceof Response) {
      return body;
    }

    if (!roleAtLeast(role, body.role)) {
      return c.json(
        adminErrorBody(
          "forbidden",
          `You cannot mint a ${body.role} token, which is above your own ${role}`,
        ),
        statusForAdminError("forbidden"),
      );
    }

    const value = generateOpaqueToken();
    const token = await createApiToken(context.db, scope, {
      name: body.name,
      tokenHash: await hashToken(value),
      role: body.role,
      createdBy: principalAdminUserId(c.get("principal")),
      expiresAt: body.expiresAt ?? null,
    });

    await recordAdminEvent(context, c, {
      action: "api-token.created",
      target: { type: "api-token", id: token.id },
      detail: { name: token.name, role: token.role },
    });

    c.header("Cache-Control", "no-store");
    return c.json({ token: apiTokenView(token), value }, 201);
  });

  /** Revokes a personal access token. */
  router.delete(
    `${TENANT_PATH}/api-tokens/:tokenId`,
    requireRole("admin"),
    async (c) => {
      const { scope } = c.get("tenant");
      const tokenId = c.req.param("tokenId");

      const revoked = await revokeApiToken(
        context.db,
        scope,
        tokenId,
        context.clock(),
      );
      if (!revoked) {
        return c.json(
          adminErrorBody("not_found", "No such live token"),
          statusForAdminError("not_found"),
        );
      }

      await recordAdminEvent(context, c, {
        action: "api-token.revoked",
        target: { type: "api-token", id: tokenId },
      });

      return c.body(null, 204);
    },
  );

  /** Reads the tenant itself. */
  router.get(TENANT_PATH, requireRole("viewer"), async (c) => {
    const { scope, role } = c.get("tenant");
    const tenant = await withTenantScope(context.db, scope, (bound) =>
      getTenant(bound),
    );
    if (tenant === undefined) {
      return c.json(
        adminErrorBody("not_found", "No such tenant"),
        statusForAdminError("not_found"),
      );
    }
    return c.json({
      tenant: { slug: tenant.slug, name: tenant.name },
      role,
    });
  });
}
