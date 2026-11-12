/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * End users and personas.
 *
 * A persona is an account with no password, seeded with a launch context so that a
 * connectathon launch works without an EHR. Personas may be *created* on any
 * endpoint but are only *selectable* on one flagged non-production - that rule lives
 * in the data layer's `isPersonaSelectable` and is checked at sign-in, which is the
 * only place it can be enforced. Allowing creation either way lets an endpoint be
 * seeded before it is promoted, and refusing selection is what stops a production
 * endpoint from handing out password-free logins.
 *
 * Disabling is preferred to deleting throughout. A disabled account stops
 * authenticating on the next request, keeps its name attached to its audit trail, and
 * leaves the consents it granted visible; deleting it takes all three away. Both are
 * available, and the console leads with the first.
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
  toLaunchContext,
} from "@signet/core";
import {
  cancelEndUserInvitation,
  createEndUser,
  deleteEndUser,
  findOutstandingEndUserInvitation,
  generateOpaqueToken,
  getEndUser,
  hashPassword,
  hashToken,
  isUniqueViolation,
  issueEndUserInvitation,
  listEndUsers,
  setEndUserDisabled,
  setEndUserPasswordHash,
  updateEndUser,
  withTenantScope,
} from "@signet/db";

import { recordAdminEvent } from "./auditTrail.js";
import { requireRole } from "./authentication.js";
import { adminErrorBody, statusForAdminError } from "./errors.js";
import { ENDPOINT_PATH } from "./paths.js";
import { parseBody } from "./requestBody.js";
import { refuseSmartOnly, smartOnlyUserFields } from "./smartOnly.js";
import { endUserView, invitationView } from "./views.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { EndpointScope, EndUser } from "@signet/db";
import type { Context, Hono } from "hono";

/** An endpoint-scoped route acting on one existing user. */
interface EndUserRoute {
  readonly scope: EndpointScope;
  readonly userId: string;
  readonly user: EndUser;
}

/**
 * Resolves the user named in the path, or the 404 to answer with.
 *
 * Every route below needs the same three things and would otherwise repeat the same
 * preamble, one copy of which would eventually forget the endpoint predicate - and a
 * user lookup without one would reach another endpoint's account.
 *
 * @param c - The Hono request context.
 * @param context - The server's dependencies.
 */
async function loadEndUserRoute(
  c: Context<SignetEnvironment>,
  context: ServerContext,
): Promise<EndUserRoute | Response> {
  const { scope } = c.get("endpoint");
  const userId = c.req.param("userId") ?? "";
  const user = await withTenantScope(context.db, scope, (bound) =>
    getEndUser(bound, userId),
  );
  if (user === undefined) {
    return c.json(
      adminErrorBody("not_found", "No such user on this endpoint"),
      statusForAdminError("not_found"),
    );
  }
  return { scope, userId, user };
}

/**
 * Registers the end user routes.
 *
 * @param router - The admin API router.
 * @param context - The server's dependencies.
 */
export function registerEndUserRoutes(
  router: Hono<SignetEnvironment>,
  context: ServerContext,
): void {
  /** Lists the endpoint's users and personas. */
  router.get(`${ENDPOINT_PATH}/users`, requireRole("viewer"), async (c) => {
    const { scope } = c.get("endpoint");
    const users = await withTenantScope(context.db, scope, (bound) =>
      listEndUsers(bound),
    );
    return c.json({ users: users.map(endUserView) });
  });

  /**
   * Fetches one user.
   *
   * The body is `endUserView` under a `user` key - the same element the list
   * returns - so the console's detail page and its table can never disagree about
   * what a user is. Read parity with the list: `viewer` and above.
   */
  router.get(
    `${ENDPOINT_PATH}/users/:userId`,
    requireRole("viewer"),
    async (c) => {
      const route = await loadEndUserRoute(c, context);
      if (route instanceof Response) {
        return route;
      }
      return c.json({ user: endUserView(route.user) });
    },
  );

  /** Creates a local account or a persona. */
  router.post(`${ENDPOINT_PATH}/users`, requireRole("admin"), async (c) => {
    const { scope, endpoint } = c.get("endpoint");
    const body = await parseBody(c, endUserCreateSchema);
    if (body instanceof Response) {
      return body;
    }
    const refusal = refuseSmartOnly(
      c,
      smartOnlyUserFields(endpoint.kind, body),
    );
    if (refusal !== undefined) {
      return refusal;
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
          ...(body.fhirUserReference === undefined
            ? {}
            : { fhirUserReference: body.fhirUserReference }),
          ...(body.email === undefined ? {} : { email: body.email }),
          ...(body.emailVerified === undefined
            ? {}
            : { emailVerified: body.emailVerified }),
          ...(body.roles === undefined ? {} : { roles: body.roles }),
          ...(body.attributes === undefined
            ? {}
            : { attributes: body.attributes }),
          ...(body.defaultContext === undefined || body.defaultContext === null
            ? {}
            : { defaultContext: toLaunchContext(body.defaultContext) }),
        }),
      );
    } catch (error) {
      if (isUniqueViolation(error)) {
        return c.json(
          adminErrorBody(
            "conflict",
            "This endpoint already has a user with that username",
          ),
          statusForAdminError("conflict"),
        );
      }
      throw error;
    }

    await recordAdminEvent(context, c, {
      action: "end-user.created",
      target: { type: "end-user", id: user.id },
      detail: {
        username: user.username,
        isPersona: user.isPersona,
        endpointSlug: endpoint.slug,
      },
    });

    return c.json({ user: endUserView(user) }, 201);
  });

  /**
   * Edits a user, including enabling or disabling them.
   *
   * The username is not editable: it is what a stored consent and an audit trail name
   * the person by. Neither is the password, which has its own route and its own audit
   * event - a display-name change and a credential change should not be
   * indistinguishable in the trail.
   */
  router.patch(
    `${ENDPOINT_PATH}/users/:userId`,
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
      const refusal = refuseSmartOnly(
        c,
        smartOnlyUserFields(c.get("endpoint").endpoint.kind, body),
      );
      if (refusal !== undefined) {
        return refusal;
      }

      const { disabled, defaultContext, ...fields } = body;
      const patch: Record<string, unknown> = Object.fromEntries(
        Object.entries(fields).filter(([, value]) => value !== undefined),
      );
      // Normalised rather than passed through: a patch carrying
      // `{ patient: undefined }` would otherwise store a key holding nothing, and a
      // seeded context is read back as a launch context where presence is the signal.
      if (defaultContext !== undefined) {
        patch["defaultContext"] =
          defaultContext === null ? null : toLaunchContext(defaultContext);
      }

      let user = existing;
      if (Object.keys(patch).length > 0) {
        const updated = await withTenantScope(context.db, scope, (bound) =>
          updateEndUser(bound, userId, patch),
        );
        if (updated === undefined) {
          return c.json(
            adminErrorBody("not_found", "No such user on this endpoint"),
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

      return c.json({ user: endUserView(user) });
    },
  );

  /**
   * Sets a user's password.
   *
   * Refused for a persona: a persona with a password would be selectable from the
   * picker *and* able to sign in, which is two authentication paths where the model
   * has one.
   */
  router.post(
    `${ENDPOINT_PATH}/users/:userId/password`,
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
    `${ENDPOINT_PATH}/users/:userId/invitation`,
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
   * The link is returned once and only its digest is stored, so the console shows it
   * to the administrator in the response to this request and never again. Refused for
   * an account that could not sign in with the password it would choose; the rule is
   * `invitationRefusal` in `@signet/core`, which the console also uses to decide
   * whether to offer the action.
   */
  router.post(
    `${ENDPOINT_PATH}/users/:userId/invitation`,
    requireRole("admin"),
    async (c) => {
      const route = await loadEndUserRoute(c, context);
      if (route instanceof Response) {
        return route;
      }
      const { endpoint, issuer } = c.get("endpoint");
      const refusal = invitationRefusal(endpoint, route.user);
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
            url: invitationUrl(issuer, token),
            ...invitationView(invitation),
          },
        },
        201,
      );
    },
  );

  /** Withdraws a user's outstanding invitation, so its link stops working. */
  router.delete(
    `${ENDPOINT_PATH}/users/:userId/invitation`,
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

  /** Deletes a user, and the consents and tokens that hang off them. */
  router.delete(
    `${ENDPOINT_PATH}/users/:userId`,
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
