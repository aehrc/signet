/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Recording what an admin API call did.
 *
 * Every mutating route writes an audit event, and each one has the same tenant,
 * endpoint and actor - all three already established by the middleware. Writing
 * that out at thirty call sites would invite one of them to name the wrong endpoint,
 * or to attribute a token's action to the person who created the token.
 *
 * The actor comes from the principal, so a personal access token appears as itself
 * rather than as its creator: revoking a script's access and revoking a person's are
 * different acts, and the trail has to make them distinguishable after the fact.
 *
 * Author: John Grimes
 */

import { principalActor } from "./principal.js";
import { requestMetadata } from "../http/requestMeta.js";

import type {
  AdminEndpointContext,
  ServerContext,
  SignetEnvironment,
} from "../context.js";
import type { AuditAction, AuditTarget } from "@signet/db";
import type { Context } from "hono";

/** What happened, beyond what the request context already establishes. */
export interface AdminAuditEvent {
  readonly action: AuditAction;
  readonly target: AuditTarget;
  /** Anything specific to this action. Never a credential. */
  readonly detail?: Record<string, unknown>;
}

/**
 * Records an event against the tenant, and the endpoint when there is one.
 *
 * The endpoint is taken from the request context rather than passed in: a route
 * below `/endpoints/:endpointSlug` has one and a tenant-level route does not, and
 * deriving it removes the possibility of a mismatch between the resource being
 * changed and the endpoint the event names.
 *
 * @param context - The server's dependencies.
 * @param c - The Hono request context, carrying the principal and the scopes.
 * @param event - The action, its target and its detail.
 */
export async function recordAdminEvent(
  context: ServerContext,
  c: Context<SignetEnvironment>,
  event: AdminAuditEvent,
): Promise<void> {
  const { scope } = c.get("tenant");
  // Widened on purpose. Hono's variable map cannot express "set only below
  // `/endpoints/:endpointSlug`", so the declared type promises a value that a
  // tenant-level route has not set; this is where that promise is not believed.
  const endpointContext: AdminEndpointContext | undefined = c.get("endpoint");

  await context.audit.record(context.db, {
    tenantId: scope.tenantId,
    ...(endpointContext === undefined
      ? {}
      : {
          endpointId: endpointContext.endpoint.id,
          endpointSlug: endpointContext.endpoint.slug,
        }),
    actor: principalActor(c.get("principal")),
    action: event.action,
    target: event.target,
    detail: event.detail ?? {},
    ...requestMetadata(c),
  });
}
