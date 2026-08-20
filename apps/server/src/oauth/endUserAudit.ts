/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Audit events attributed to an end user.
 *
 * Three surfaces write them - the interaction API, the management page and the
 * federation callback - and every one of them has the same tenant, the same
 * endpoint and the same actor shape, differing only in the action, the target and
 * the detail. Written out per surface, that was three chances to name the wrong
 * endpoint on an event that is supposed to be the record of who did what.
 *
 * The actor's identifier is optional because a failed sign-in has no account to
 * attribute: somebody typed a username that may not exist, and inventing an actor
 * for them would put a claim in the trail that nothing supports.
 *
 * Author: John Grimes
 */

import type { ServerContext, ResolvedIssuerContext } from "../context.js";
import type { requestMetadata } from "../http/requestMeta.js";
import type { AuditAction, AuditTarget } from "@signet/db";

/** One event, as a surface describes it. */
export interface EndUserAuditEvent {
  readonly action: AuditAction;
  readonly target: AuditTarget;
  readonly detail: Record<string, unknown>;
  /** Absent for a failed sign-in, where no account was established. */
  readonly endUserId?: string | null;
  readonly displayName?: string;
}

/**
 * Records an event attributed to the end user driving an interaction.
 *
 * @param context - The server's dependencies.
 * @param issuerContext - The endpoint the event happened on.
 * @param metadata - Request metadata: address and user agent.
 * @param event - The action, the target and what to say about it.
 */
export async function recordEndUserEvent(
  context: ServerContext,
  issuerContext: ResolvedIssuerContext,
  metadata: ReturnType<typeof requestMetadata>,
  event: EndUserAuditEvent,
): Promise<void> {
  await context.audit.record(context.db, {
    tenantId: issuerContext.tenant.id,
    endpointId: issuerContext.endpoint.id,
    endpointSlug: issuerContext.endpoint.slug,
    actor: {
      type: "end-user",
      ...(event.endUserId === undefined || event.endUserId === null
        ? {}
        : { id: event.endUserId }),
      ...(event.displayName === undefined
        ? {}
        : { displayName: event.displayName }),
    },
    action: event.action,
    target: event.target,
    detail: event.detail,
    ...metadata,
  });
}
