/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Which of the tenant's accounts may sign in at an endpoint, and what they are called
 * there.
 *
 * Access is explicit: an account with no access row for an endpoint cannot sign in
 * there, is not offered in its persona picker, and has its refresh tokens there
 * refused. Granting access is the rule that admits it; nothing else does.
 *
 * The access row is also where an account's endpoint-specific fields live - its
 * `fhirUser` reference and, for a persona, its default launch context - because each
 * names a resource on that endpoint's FHIR server. Both are SMART-only, so an OAuth /
 * OpenID Connect endpoint refuses them.
 *
 * Withdrawing access ends the account's consents, management sessions and in-flight
 * authorizations at this endpoint and revokes its refresh tokens there, and touches
 * nothing anywhere else.
 *
 * Author: John Grimes
 */

import { endpointAccessSchema } from "@signet/contracts";
import { toLaunchContext } from "@signet/core";
import {
  grantEndpointAccess,
  listEndpointEndUsers,
  revokeEndpointAccess,
  withTenantScope,
} from "@signet/db";

import { recordAdminEvent } from "./auditTrail.js";
import { requireRole } from "./authentication.js";
import { findTenantEndUser, respondWithEndUser } from "./endUserRoutes.js";
import { adminErrorBody, statusForAdminError } from "./errors.js";
import { ENDPOINT_PATH } from "./paths.js";
import { parseBody } from "./requestBody.js";
import { refuseSmartOnly, smartOnlyUserFields } from "./smartOnly.js";
import { endpointEndUserView } from "./views.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { EndpointAccessFields } from "@signet/db";
import type { Hono } from "hono";

/**
 * Registers the endpoint access routes.
 *
 * @param router - The admin API router.
 * @param context - The server's dependencies.
 */
export function registerEndpointAccessRoutes(
  router: Hono<SignetEnvironment>,
  context: ServerContext,
): void {
  /**
   * Lists the accounts with access to this endpoint, as the endpoint sees them.
   *
   * The policy simulator picks its user from this list, so it offers exactly the
   * accounts the issuer would admit.
   */
  router.get(`${ENDPOINT_PATH}/users`, requireRole("viewer"), async (c) => {
    const { scope } = c.get("endpoint");
    const users = await withTenantScope(context.db, scope, (bound) =>
      listEndpointEndUsers(bound),
    );
    return c.json({ users: users.map(endpointEndUserView) });
  });

  /**
   * Gives an account access to this endpoint, or updates the access it has.
   *
   * Idempotent. A field the body leaves out keeps its stored value, and null clears
   * it, so a console toggling access on does not wipe a `fhirUser` it did not send.
   */
  router.put(
    `${ENDPOINT_PATH}/users/:userId`,
    requireRole("admin"),
    async (c) => {
      const { scope, endpoint } = c.get("endpoint");
      const userId = c.req.param("userId") ?? "";
      const body = await parseBody(c, endpointAccessSchema);
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

      const user = await findTenantEndUser(context, scope, userId);
      if (user === undefined) {
        return c.json(
          adminErrorBody("not_found", "No such user in this tenant"),
          statusForAdminError("not_found"),
        );
      }

      // Normalised rather than passed through: a context carrying
      // `{ patient: undefined }` would otherwise store a key holding nothing, and a
      // seeded context is read back as a launch context where presence is the signal.
      const fields: EndpointAccessFields = {
        ...(body.fhirUserReference === undefined
          ? {}
          : { fhirUserReference: body.fhirUserReference }),
        ...(body.defaultContext === undefined
          ? {}
          : {
              defaultContext:
                body.defaultContext === null
                  ? null
                  : toLaunchContext(body.defaultContext),
            }),
      };
      await withTenantScope(context.db, scope, (bound) =>
        grantEndpointAccess(bound, userId, fields),
      );

      await recordAdminEvent(context, c, {
        action: "end-user.access-granted",
        target: { type: "end-user", id: userId },
        detail: {
          username: user.username,
          endpointSlug: endpoint.slug,
          fields: Object.keys(fields),
        },
      });

      return await respondWithEndUser(c, context, scope, user);
    },
  );

  /** Withdraws an account's access to this endpoint. */
  router.delete(
    `${ENDPOINT_PATH}/users/:userId`,
    requireRole("admin"),
    async (c) => {
      const { scope, endpoint } = c.get("endpoint");
      const userId = c.req.param("userId") ?? "";
      const user = await findTenantEndUser(context, scope, userId);
      const revoked =
        user !== undefined &&
        (await withTenantScope(context.db, scope, (bound) =>
          revokeEndpointAccess(bound, userId, context.clock()),
        ));
      if (user === undefined || !revoked) {
        return c.json(
          adminErrorBody(
            "not_found",
            "This user has no access to this endpoint",
          ),
          statusForAdminError("not_found"),
        );
      }

      await recordAdminEvent(context, c, {
        action: "end-user.access-revoked",
        target: { type: "end-user", id: userId },
        detail: { username: user.username, endpointSlug: endpoint.slug },
      });
      return c.body(null, 204);
    },
  );
}
