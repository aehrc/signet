/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * End users and personas: the tenant's accounts.
 *
 * An account belongs to the tenant, with one username and one password across all of
 * its endpoints. It signs in only at an endpoint it has been given access to, which is
 * managed per endpoint in `./endpointAccessRoutes.ts`; an account created here has
 * access to nothing.
 *
 * A persona is an account with no password, seeded with a launch context on each SMART
 * endpoint it has access to, so that a connectathon launch works without an EHR.
 * Personas may be *created* in any tenant but are only *selectable* on an endpoint
 * flagged non-production - that rule lives in the data layer's `isPersonaSelectable`
 * and is checked at sign-in, which is the only place it can be enforced.
 *
 * Disabling is preferred to deleting throughout. A disabled account stops
 * authenticating on the next request, at every endpoint, keeps its name attached to its
 * audit trail, and leaves the consents it granted visible; deleting it takes all three
 * away. Both are available, and the console leads with the first.
 *
 * Author: John Grimes
 */

import {
  endUserCreateSchema,
  endUserPasswordSchema,
  endUserPatchSchema,
} from "@signet/contracts";
import {
  INVITATION_REFUSAL_MESSAGES,
  invitationExpiry,
  invitationRefusal,
  invitationUrl,
  withEmailVerification,
} from "@signet/core";
import {
  cancelEndUserInvitation,
  createEndUser,
  deleteEndUser,
  findOutstandingEndUserInvitation,
  generateOpaqueToken,
  getTenantEndUser,
  hashPassword,
  hashToken,
  isUniqueViolation,
  issueEndUserInvitation,
  listEndpointAccess,
  listTenantEndUsers,
  setEndUserDisabled,
  setEndUserPasswordHash,
  updateEndUser,
  withTenantScope,
} from "@signet/db";

import { recordAdminEvent } from "./auditTrail.js";
import { requireRole } from "./authentication.js";
import { adminErrorBody, statusForAdminError } from "./errors.js";
import { TENANT_PATH } from "./paths.js";
import { parseBody } from "./requestBody.js";
import { endUserView, invitationView } from "./views.js";
import { tenantUrlFor } from "../oauth/issuer.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { EndUser, TenantScope } from "@signet/db";
import type { Context, Hono } from "hono";

/** A tenant route acting on one existing account. */
interface EndUserRoute {
  readonly scope: TenantScope;
  readonly userId: string;
  readonly user: EndUser;
}

/**
 * Reads one of the tenant's accounts, whatever endpoints it has access to.
 *
 * @param context - The server's dependencies.
 * @param scope - The tenant.
 * @param userId - The account's identifier, from the path.
 */
export async function findTenantEndUser(
  context: ServerContext,
  scope: TenantScope,
  userId: string,
): Promise<EndUser | undefined> {
  return await withTenantScope(context.db, scope, (bound) =>
    getTenantEndUser(bound, userId),
  );
}

/**
 * Answers with an account and the endpoints it has access to, as `{ user }`.
 *
 * @param c - The Hono request context.
 * @param context - The server's dependencies.
 * @param scope - The tenant.
 * @param user - The account.
 * @param status - The status to answer with.
 */
export async function respondWithEndUser(
  c: Context<SignetEnvironment>,
  context: ServerContext,
  scope: TenantScope,
  user: EndUser,
  status: 200 | 201 = 200,
): Promise<Response> {
  const access = await withTenantScope(context.db, scope, (bound) =>
    listEndpointAccess(bound, user.id),
  );
  return c.json({ user: endUserView(user, access) }, status);
}

/**
 * Resolves the account named in the path, or the 404 to answer with.
 *
 * @param c - The Hono request context.
 * @param context - The server's dependencies.
 */
async function loadEndUserRoute(
  c: Context<SignetEnvironment>,
  context: ServerContext,
): Promise<EndUserRoute | Response> {
  const { scope } = c.get("tenant");
  const userId = c.req.param("userId") ?? "";
  const user = await findTenantEndUser(context, scope, userId);
  if (user === undefined) {
    return c.json(
      adminErrorBody("not_found", "No such user in this tenant"),
      statusForAdminError("not_found"),
    );
  }
  return { scope, userId, user };
}

/**
 * Registers the tenant's account routes.
 *
 * @param router - The admin API router.
 * @param context - The server's dependencies.
 */
export function registerEndUserRoutes(
  router: Hono<SignetEnvironment>,
  context: ServerContext,
): void {
  /** Lists the tenant's users and personas, each with the endpoints they can use. */
  router.get(`${TENANT_PATH}/users`, requireRole("viewer"), async (c) => {
    const { scope } = c.get("tenant");
    const { users, access } = await withTenantScope(
      context.db,
      scope,
      async (bound) => ({
        users: await listTenantEndUsers(bound),
        access: await listEndpointAccess(bound),
      }),
    );
    return c.json({ users: users.map((user) => endUserView(user, access)) });
  });

  /**
   * Fetches one user.
   *
   * The body is `endUserView` under a `user` key - the same element the list
   * returns - so the console's detail page and its table can never disagree about
   * what a user is. Read parity with the list: `viewer` and above.
   */
  router.get(
    `${TENANT_PATH}/users/:userId`,
    requireRole("viewer"),
    async (c) => {
      const route = await loadEndUserRoute(c, context);
      if (route instanceof Response) {
        return route;
      }
      return await respondWithEndUser(c, context, route.scope, route.user);
    },
  );

  /** Creates a local account or a persona, with access to no endpoint yet. */
  router.post(`${TENANT_PATH}/users`, requireRole("admin"), async (c) => {
    const { scope } = c.get("tenant");
    const body = await parseBody(c, endUserCreateSchema);
    if (body instanceof Response) {
      return body;
    }

    let user;
    try {
      user = await withTenantScope(context.db, scope, async (bound) =>
        createEndUser(bound, {
          username: body.username,
          displayName: body.displayName,
          isPersona: body.isPersona ?? false,
          ...(body.password === undefined
            ? {}
            : { passwordHash: await hashPassword(body.password) }),
          ...(body.email === undefined ? {} : { email: body.email }),
          ...(body.emailVerified === undefined
            ? {}
            : { emailVerified: body.emailVerified }),
          ...(body.roles === undefined ? {} : { roles: body.roles }),
          ...(body.attributes === undefined
            ? {}
            : { attributes: body.attributes }),
        }),
      );
    } catch (error) {
      if (isUniqueViolation(error)) {
        return c.json(
          adminErrorBody(
            "conflict",
            "This tenant already has a user with that username",
          ),
          statusForAdminError("conflict"),
        );
      }
      throw error;
    }

    await recordAdminEvent(context, c, {
      action: "end-user.created",
      target: { type: "end-user", id: user.id },
      detail: { username: user.username, isPersona: user.isPersona },
    });

    return c.json({ user: endUserView(user, []) }, 201);
  });

  /**
   * Edits a user, including enabling or disabling them.
   *
   * The username is not editable: it is what a stored consent and an audit trail name
   * the person by. Neither is the password, which has its own route and its own audit
   * event - a display-name change and a credential change should not be
   * indistinguishable in the trail. What a user is called at one endpoint is edited
   * with their access to it.
   */
  router.patch(
    `${TENANT_PATH}/users/:userId`,
    requireRole("admin"),
    async (c) => {
      const route = await loadEndUserRoute(c, context);
      if (route instanceof Response) {
        return route;
      }
      const { scope, userId, user: existing } = route;

      const body = await parseBody(c, endUserPatchSchema);
      if (body instanceof Response) {
        return body;
      }

      // A changed or cleared address loses its verified flag unless this same edit
      // vouches for it again; see `withEmailVerification`.
      const { disabled, ...fields } = withEmailVerification(existing, body);
      const patch: Record<string, unknown> = Object.fromEntries(
        Object.entries(fields).filter(([, value]) => value !== undefined),
      );

      let user = existing;
      if (Object.keys(patch).length > 0) {
        const updated = await withTenantScope(context.db, scope, (bound) =>
          updateEndUser(bound, userId, patch),
        );
        if (updated === undefined) {
          return c.json(
            adminErrorBody("not_found", "No such user in this tenant"),
            statusForAdminError("not_found"),
          );
        }
        user = updated;
      }

      if (disabled !== undefined) {
        const toggled = await withTenantScope(context.db, scope, (bound) =>
          setEndUserDisabled(bound, userId, disabled, context.clock()),
        );
        if (toggled !== undefined) {
          user = toggled;
        }
      }

      await recordAdminEvent(context, c, {
        action:
          disabled === true && existing.disabledAt === null
            ? "end-user.disabled"
            : "end-user.updated",
        target: { type: "end-user", id: userId },
        detail: {
          fields: Object.keys(patch),
          ...(disabled === undefined ? {} : { disabled }),
        },
      });

      return await respondWithEndUser(c, context, scope, user);
    },
  );

  /**
   * Sets a user's password, which is the one password at every endpoint they can use.
   *
   * Refused for a persona: a persona with a password would be selectable from the
   * picker *and* able to sign in, which is two authentication paths where the model
   * has one.
   */
  router.post(
    `${TENANT_PATH}/users/:userId/password`,
    requireRole("admin"),
    async (c) => {
      const route = await loadEndUserRoute(c, context);
      if (route instanceof Response) {
        return route;
      }
      const { scope, userId, user: existing } = route;
      if (existing.isPersona) {
        return c.json(
          adminErrorBody(
            "invalid_request",
            "A persona has no password: it is selected from a picker, not signed into",
          ),
          statusForAdminError("invalid_request"),
        );
      }

      const body = await parseBody(c, endUserPasswordSchema);
      if (body instanceof Response) {
        return body;
      }

      await withTenantScope(context.db, scope, async (bound) =>
        setEndUserPasswordHash(
          bound,
          userId,
          await hashPassword(body.password),
        ),
      );

      await recordAdminEvent(context, c, {
        action: "end-user.updated",
        target: { type: "end-user", id: userId },
        detail: { passwordChanged: true },
      });

      return c.body(null, 204);
    },
  );

  /** Reports whether a user has an outstanding invitation, and when it expires. */
  router.get(
    `${TENANT_PATH}/users/:userId/invitation`,
    requireRole("viewer"),
    async (c) => {
      const route = await loadEndUserRoute(c, context);
      if (route instanceof Response) {
        return route;
      }
      const invitation = await withTenantScope(
        context.db,
        route.scope,
        (bound) =>
          findOutstandingEndUserInvitation(
            bound,
            route.userId,
            context.clock(),
          ),
      );
      return c.json({
        invitation:
          invitation === undefined ? null : invitationView(invitation),
      });
    },
  );

  /**
   * Issues an invitation link, replacing any the user already has.
   *
   * The link opens the tenant's invitation page, since the password it sets is the
   * account's at every endpoint. It is returned once and only its digest is stored, so
   * the console shows it to the administrator in the response to this request and never
   * again. Refused for an account that could not sign in anywhere with the password it
   * would choose; the rule is `invitationRefusal` in `@signet/core`, which the console
   * also uses to decide whether to offer the action.
   */
  router.post(
    `${TENANT_PATH}/users/:userId/invitation`,
    requireRole("admin"),
    async (c) => {
      const route = await loadEndUserRoute(c, context);
      if (route instanceof Response) {
        return route;
      }
      const access = await withTenantScope(context.db, route.scope, (bound) =>
        listEndpointAccess(bound, route.userId),
      );
      const refusal = invitationRefusal(
        route.user,
        access.map((row) => ({ authMode: row.endpointAuthMode })),
      );
      if (refusal !== undefined) {
        return c.json(
          adminErrorBody(
            "invalid_request",
            INVITATION_REFUSAL_MESSAGES[refusal],
          ),
          statusForAdminError("invalid_request"),
        );
      }

      const token = generateOpaqueToken();
      const tokenHash = await hashToken(token);
      const invitation = await withTenantScope(
        context.db,
        route.scope,
        (bound) =>
          issueEndUserInvitation(bound, {
            endUserId: route.userId,
            tokenHash,
            expiresAt: invitationExpiry(context.clock()),
          }),
      );

      await recordAdminEvent(context, c, {
        action: "end-user.invited",
        target: { type: "end-user", id: route.userId },
        detail: {
          username: route.user.username,
          expiresAt: invitation.expiresAt.toISOString(),
        },
      });

      c.header("Cache-Control", "no-store");
      return c.json(
        {
          invitation: {
            url: invitationUrl(
              tenantUrlFor(context.config.publicUrl, route.scope.tenantSlug),
              token,
            ),
            ...invitationView(invitation),
          },
        },
        201,
      );
    },
  );

  /** Withdraws a user's outstanding invitation, so its link stops working. */
  router.delete(
    `${TENANT_PATH}/users/:userId/invitation`,
    requireRole("admin"),
    async (c) => {
      const route = await loadEndUserRoute(c, context);
      if (route instanceof Response) {
        return route;
      }
      const cancelled = await withTenantScope(
        context.db,
        route.scope,
        (bound) =>
          cancelEndUserInvitation(bound, route.userId, context.clock()),
      );
      if (!cancelled) {
        return c.json(
          adminErrorBody(
            "not_found",
            "This user has no outstanding invitation",
          ),
          statusForAdminError("not_found"),
        );
      }

      await recordAdminEvent(context, c, {
        action: "end-user.invitation-cancelled",
        target: { type: "end-user", id: route.userId },
        detail: { username: route.user.username },
      });
      return c.body(null, 204);
    },
  );

  /**
   * Deletes a user, and the access, consents and tokens that hang off them at every
   * endpoint.
   */
  router.delete(
    `${TENANT_PATH}/users/:userId`,
    requireRole("admin"),
    async (c) => {
      const route = await loadEndUserRoute(c, context);
      if (route instanceof Response) {
        return route;
      }

      // Recorded before the delete, while the username is still readable: the event
      // has to say who was removed, and afterwards there is no row to ask.
      await recordAdminEvent(context, c, {
        action: "end-user.updated",
        target: { type: "end-user", id: route.userId },
        detail: { deleted: true, username: route.user.username },
      });

      await withTenantScope(context.db, route.scope, (bound) =>
        deleteEndUser(bound, route.userId),
      );
      return c.body(null, 204);
    },
  );
}
