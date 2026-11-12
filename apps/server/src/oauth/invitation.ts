/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The API behind the invitation page, where an invitee chooses their password.
 *
 * An administrator mints the link in the console (see `../admin/endUserRoutes.ts`) and
 * sends it from their own mail client. The link points at `{iss}/invitation` with the
 * token in its fragment, and the page presents the token here in a request body, so it
 * never appears in a URL that a server or proxy logs.
 *
 * Every refusal gets the same answer. A link that never existed, one that expired, one
 * that was replaced or cancelled, one already used, and one for an account that has
 * since been disabled or whose endpoint has since begun to federate are all "this link
 * is not valid": telling them apart would tell a holder of a stale link something about
 * the account it named, and none of them is something the holder can fix.
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
  hashPassword,
  hashToken,
  redeemEndUserInvitation,
  withTenantScope,
} from "@signet/db";

import { requestMetadata } from "../http/requestMeta.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { BoundEndpointScope, Endpoint, InvitedEndUser } from "@signet/db";
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
 * issued. The endpoint's auth mode or the account's state may have changed since.
 */
async function usableInvitation(
  bound: BoundEndpointScope,
  endpoint: Endpoint,
  tokenHash: string,
  now: Date,
): Promise<InvitedEndUser | undefined> {
  const found = await findEndUserByInvitation(bound, tokenHash, now);
  return found === undefined ||
    invitationRefusal(endpoint, found.user) !== undefined
    ? undefined
    : found;
}

/**
 * Handles `POST {iss}/invitation/details`: which account a link is for.
 *
 * The page shows the invitee the endpoint, their name and the username they will
 * sign in with before they choose a password. Does not spend the link.
 *
 * @param context - The server's dependencies.
 * @returns The Hono handler.
 */
export function invitationDetailsHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const { scope, endpoint } = c.get("issuer");
    const body = await readBody(c, invitationDetailsSchema);
    if (body instanceof Response) {
      return body;
    }

    const tokenHash = await hashToken(body.token);
    const found = await withTenantScope(context.db, scope, (bound) =>
      usableInvitation(bound, endpoint, tokenHash, context.clock()),
    );
    if (found === undefined) {
      return invalidInvitation(c);
    }

    c.header("Cache-Control", "no-store");
    return c.json({
      username: found.user.username,
      displayName: found.user.displayName,
      expiresAt: found.invitation.expiresAt,
      endpointName: endpoint.name,
    });
  };
}

/**
 * Handles `POST {iss}/invitation/accept`: chooses the password and spends the link.
 *
 * The password is hashed before the link is looked up, so a valid and an invalid link
 * cost the same and the transaction that spends the link is not held open across an
 * Argon2id computation.
 *
 * @param context - The server's dependencies.
 * @returns The Hono handler.
 */
export function invitationAcceptHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const issuerContext = c.get("issuer");
    const { scope, endpoint } = issuerContext;
    const body = await readBody(c, invitationAcceptSchema);
    if (body instanceof Response) {
      return body;
    }

    const passwordHash = await hashPassword(body.password);
    const tokenHash = await hashToken(body.token);
    const now = context.clock();
    const user = await withTenantScope(context.db, scope, async (bound) =>
      (await usableInvitation(bound, endpoint, tokenHash, now)) === undefined
        ? undefined
        : await redeemEndUserInvitation(bound, tokenHash, passwordHash, now),
    );
    if (user === undefined) {
      return invalidInvitation(c);
    }

    await context.audit.record(context.db, {
      tenantId: issuerContext.tenant.id,
      endpointId: endpoint.id,
      endpointSlug: endpoint.slug,
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
