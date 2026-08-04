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
import { toLaunchContext } from "@signet/core";
import {
  createEndUser,
  deleteEndUser,
  getEndUser,
  hashPassword,
  isUniqueViolation,
  listEndUsers,
  setEndUserDisabled,
  setEndUserPasswordHash,
  updateEndUser,
} from "@signet/db";

import { recordAdminEvent } from "./auditTrail.js";
import { requireRole } from "./authentication.js";
import { adminErrorBody, statusForAdminError } from "./errors.js";
import { ENDPOINT_PATH } from "./paths.js";
import { parseBody } from "./requestBody.js";
import { endUserView } from "./views.js";

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
  const user = await getEndUser(context.db, scope, userId);
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
    const users = await listEndUsers(context.db, scope);
    return c.json({ users: users.map(endUserView) });
  });

  /** Creates a local account or a persona. */
  router.post(`${ENDPOINT_PATH}/users`, requireRole("admin"), async (c) => {
    const { scope, endpoint } = c.get("endpoint");
    const body = await parseBody(c, endUserCreateSchema);
    if (body instanceof Response) {
      return body;
    }

    let user;
    try {
      user = await createEndUser(context.db, scope, {
        username: body.username,
        displayName: body.displayName,
        isPersona: body.isPersona ?? false,
        ...(body.password === undefined
          ? {}
          : { passwordHash: await hashPassword(body.password) }),
        ...(body.fhirUserReference === undefined
          ? {}
          : { fhirUserReference: body.fhirUserReference }),
        ...(body.roles === undefined ? {} : { roles: body.roles }),
        ...(body.attributes === undefined
          ? {}
          : { attributes: body.attributes }),
        ...(body.defaultContext === undefined || body.defaultContext === null
          ? {}
          : { defaultContext: toLaunchContext(body.defaultContext) }),
      });
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
        const updated = await updateEndUser(context.db, scope, userId, patch);
        if (updated === undefined) {
          return c.json(
            adminErrorBody("not_found", "No such user on this endpoint"),
            statusForAdminError("not_found"),
          );
        }
        user = updated;
      }

      if (disabled !== undefined) {
        const toggled = await setEndUserDisabled(
          context.db,
          scope,
          userId,
          disabled,
          context.clock(),
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

      await setEndUserPasswordHash(
        context.db,
        scope,
        userId,
        await hashPassword(body.password),
      );

      await recordAdminEvent(context, c, {
        action: "end-user.updated",
        target: { type: "end-user", id: userId },
        detail: { passwordChanged: true },
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

      await deleteEndUser(context.db, route.scope, route.userId);
      return c.body(null, 204);
    },
  );
}
