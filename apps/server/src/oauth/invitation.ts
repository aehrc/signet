/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The API behind the invitation page, where an invitee chooses their password.
 *
 * An administrator mints the link in the console (see `../admin/endUserRoutes.ts`) and
 * sends it from their own mail client. An account belongs to the tenant, and the
 * password it chooses is checked at every endpoint in local auth mode it has access to,
 * so the link points at the tenant's page, `/t/{tenant}/invitation`, rather than at any
 * one endpoint. The token is in the link's fragment, and the page presents it here in a
 * request body, so it never appears in a URL that a server or proxy logs.
 *
 * Every refusal gets the same answer. A link that never existed, one that expired, one
 * that was replaced or cancelled, one already used, one presented to another tenant, and
 * one for an account that has since been disabled or no longer has access to any
 * endpoint that checks a password are all "this link is not valid": telling them apart
 * would tell a holder of a stale link something about the account it named, and none of
 * them is something the holder can fix.
 *
 * Author: John Grimes
 */

import {
  invitationAcceptSchema,
  invitationDetailsSchema,
} from "@signet/contracts";
import { invitationRefusal } from "@signet/core";
import {
  findEndUserByInvitation,
  getTenant,
  hashPassword,
  hashToken,
  listEndpointAccess,
  redeemEndUserInvitation,
  resolveTenantScope,
  withTenantScope,
} from "@signet/db";
import { Hono } from "hono";

import { rateLimit } from "../http/rateLimit.js";
import { requestMetadata } from "../http/requestMeta.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { BoundTenantScope, InvitedEndUser } from "@signet/db";
import type { Context } from "hono";
import type { ZodType } from "zod";

/** The one answer every unusable link gets. */
function invalidInvitation(c: Context<SignetEnvironment>) {
  return c.json(
    {
      error: "invalid_invitation",
      error_description:
        "This invitation link is not valid. It may have expired, been replaced or already been used.",
    },
    404,
  );
}

/**
 * Reads and validates a body, or answers 400 in the OAuth error shape the other
 * end-user pages read, with the first problem as the description.
 */
async function readBody<T>(
  c: Context<SignetEnvironment>,
  schema: ZodType<T>,
): Promise<T | Response> {
  const { success, data, error } = schema.safeParse(
    await c.req.json().catch(() => null),
  );
  return success
    ? data
    : c.json(
        {
          error: "invalid_request",
          error_description: error.issues[0]?.message ?? "Invalid request",
        },
        400,
      );
}

/**
 * Finds the account a link is for, applying the same rule that decided it could be
 * issued. The account's state, the endpoints it has access to and their auth modes may
 * all have changed since.
 */
async function usableInvitation(
  bound: BoundTenantScope,
  tokenHash: string,
  now: Date,
): Promise<InvitedEndUser | undefined> {
  const found = await findEndUserByInvitation(bound, tokenHash, now);
  if (found === undefined) {
    return undefined;
  }
  const access = await listEndpointAccess(bound, found.user.id);
  return invitationRefusal(
    found.user,
    access.map((row) => ({ authMode: row.endpointAuthMode })),
  ) === undefined
    ? found
    : undefined;
}

/**
 * Handles `POST /t/{tenant}/invitation/details`: which account a link is for.
 *
 * The page shows the invitee the tenant, their name and the username they will sign in
 * with before they choose a password. Does not spend the link.
 *
 * @param context - The server's dependencies.
 * @returns The Hono handler.
 */
function invitationDetailsHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const body = await readBody(c, invitationDetailsSchema);
    if (body instanceof Response) {
      return body;
    }
    const scope = await resolveTenantScope(
      context.db,
      c.req.param("tenantSlug") ?? "",
    );
    if (scope === undefined) {
      return invalidInvitation(c);
    }

    const tokenHash = await hashToken(body.token);
    const found = await withTenantScope(context.db, scope, async (bound) => {
      const invited = await usableInvitation(bound, tokenHash, context.clock());
      const tenant = invited === undefined ? undefined : await getTenant(bound);
      return invited === undefined || tenant === undefined
        ? undefined
        : { ...invited, tenantName: tenant.name };
    });
    if (found === undefined) {
      return invalidInvitation(c);
    }

    c.header("Cache-Control", "no-store");
    return c.json({
      username: found.user.username,
      displayName: found.user.displayName,
      expiresAt: found.invitation.expiresAt,
      tenantName: found.tenantName,
    });
  };
}

/**
 * Handles `POST /t/{tenant}/invitation/accept`: chooses the password and spends the
 * link.
 *
 * The password is hashed before the link is looked up, so a valid and an invalid link
 * cost the same and the transaction that spends the link is not held open across an
 * Argon2id computation.
 *
 * @param context - The server's dependencies.
 * @returns The Hono handler.
 */
function invitationAcceptHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const body = await readBody(c, invitationAcceptSchema);
    if (body instanceof Response) {
      return body;
    }

    const passwordHash = await hashPassword(body.password);
    const tokenHash = await hashToken(body.token);
    const scope = await resolveTenantScope(
      context.db,
      c.req.param("tenantSlug") ?? "",
    );
    if (scope === undefined) {
      return invalidInvitation(c);
    }
    const now = context.clock();
    const user = await withTenantScope(context.db, scope, async (bound) =>
      (await usableInvitation(bound, tokenHash, now)) === undefined
        ? undefined
        : await redeemEndUserInvitation(bound, tokenHash, passwordHash, now),
    );
    if (user === undefined) {
      return invalidInvitation(c);
    }

    // A tenant-level event: the password is the account's at every endpoint, so no one
    // endpoint is where this happened.
    await context.audit.record(context.db, {
      tenantId: scope.tenantId,
      actor: { type: "end-user", id: user.id, displayName: user.displayName },
      action: "end-user.invitation-accepted",
      target: { type: "end-user", id: user.id },
      detail: { username: user.username },
      ...requestMetadata(context, c),
    });

    c.header("Cache-Control", "no-store");
    return c.json({ username: user.username });
  };
}

/**
 * Builds the router for `/t/:tenantSlug/invitation/details` and `/accept`.
 *
 * Both routes take a bearer token from a caller with no other credential, and the
 * second sets a password with it, so both are limited as sign-in is. The limiter keys
 * on the matched route and the client address, never the body, so each route gets an
 * allowance of its own and nobody can spend another caller's.
 *
 * @param context - The server's dependencies.
 * @returns The router, to be mounted at the root.
 */
export function createInvitationRouter(
  context: ServerContext,
): Hono<SignetEnvironment> {
  const router = new Hono<SignetEnvironment>();
  router.post(
    "/t/:tenantSlug/invitation/details",
    rateLimit("signIn", context),
    invitationDetailsHandler(context),
  );
  router.post(
    "/t/:tenantSlug/invitation/accept",
    rateLimit("signIn", context),
    invitationAcceptHandler(context),
  );
  return router;
}
