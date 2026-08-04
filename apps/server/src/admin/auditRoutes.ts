/**
 * The audit browser's read side.
 *
 * Paging is keyset rather than offset, because `audit_events` only grows: an offset
 * page ten thousand rows in costs the database ten thousand rows, and a row inserted
 * between two requests shifts every subsequent page. The cursor is the data layer's
 * `{ at, id }` position, opaque to the caller - encoded here as base64url so that a
 * client cannot compose a position by hand and ask for a page boundary that never
 * existed.
 *
 * Filters are refused rather than ignored when they are malformed. An audit search
 * that quietly dropped a constraint it did not understand would answer "nothing
 * matched", which is a different and much worse answer than "that filter is not
 * valid".
 *
 * The tenant is not a filter. It comes from the scope the middleware resolved, and
 * `queryAuditEvents` requires it - so there is no request shape that reads across
 * tenants.
 *
 * Author: John Grimes
 */

import { auditQuerySchema } from "@signet/contracts";
import {
  getEndpointBySlug,
  isAuditAction,
  isAuditTargetType,
  queryAuditEvents,
  withTenantScope,
} from "@signet/db";

import { requireRole } from "./authentication.js";
import { adminErrorBody, statusForAdminError } from "./errors.js";
import { TENANT_PATH } from "./paths.js";
import { parseQuery } from "./requestBody.js";
import { auditEventView } from "./views.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { AuditAction, AuditEventCursor } from "@signet/db";
import type { Hono } from "hono";

/**
 * Encodes a keyset position as an opaque string.
 *
 * @param cursor - The position the data layer reported.
 */
export function encodeAuditCursor(cursor: AuditEventCursor): string {
  return Buffer.from(
    JSON.stringify({ at: cursor.at.toISOString(), id: cursor.id }),
    "utf8",
  ).toString("base64url");
}

/**
 * Decodes a cursor the client sent back.
 *
 * Returns undefined for anything malformed, and the caller treats that as an
 * invalid request. Silently starting from the beginning instead would answer a
 * request for page nine with page one.
 *
 * @param raw - The `cursor` query parameter.
 */
export function decodeAuditCursor(raw: string): AuditEventCursor | undefined {
  try {
    const parsed = JSON.parse(
      Buffer.from(raw, "base64url").toString("utf8"),
    ) as { at?: unknown; id?: unknown };
    if (typeof parsed.at !== "string" || typeof parsed.id !== "string") {
      return undefined;
    }
    const at = new Date(parsed.at);
    if (Number.isNaN(at.getTime())) {
      return undefined;
    }
    return { at, id: parsed.id };
  } catch {
    return undefined;
  }
}

/** Collects the `action` parameter, whether it arrived once or many times. */
function requestedActions(action: string | readonly string[] | undefined): {
  readonly actions: AuditAction[];
  readonly unrecognised: string[];
} {
  const raw = action === undefined ? [] : [action].flat();
  return {
    actions: raw.filter((candidate): candidate is AuditAction =>
      isAuditAction(candidate),
    ),
    unrecognised: raw.filter((candidate) => !isAuditAction(candidate)),
  };
}

/**
 * Registers the audit browser route.
 *
 * @param router - The admin API router.
 * @param context - The server's dependencies.
 */
export function registerAuditRoutes(
  router: Hono<SignetEnvironment>,
  context: ServerContext,
): void {
  /** Reads one page of the tenant's audit trail. */
  router.get(`${TENANT_PATH}/audit`, requireRole("viewer"), async (c) => {
    const { scope } = c.get("tenant");
    const query = parseQuery(c, auditQuerySchema);
    if (query instanceof Response) {
      return query;
    }

    const { actions, unrecognised } = requestedActions(query.action);
    if (unrecognised.length > 0) {
      return c.json(
        adminErrorBody(
          "invalid_request",
          `Not an action this deployment records: ${unrecognised.join(", ")}`,
        ),
        statusForAdminError("invalid_request"),
      );
    }

    if (
      query.targetType !== undefined &&
      !isAuditTargetType(query.targetType)
    ) {
      return c.json(
        adminErrorBody(
          "invalid_request",
          `Not a target type this deployment records: ${query.targetType}`,
        ),
        statusForAdminError("invalid_request"),
      );
    }
    const targetType = query.targetType;

    let endpointId: string | undefined;
    const endpointSlug = query.endpointSlug;
    if (endpointSlug !== undefined) {
      const endpoint = await withTenantScope(context.db, scope, (bound) =>
        getEndpointBySlug(bound, endpointSlug),
      );
      if (endpoint === undefined) {
        return c.json(
          adminErrorBody("not_found", "No such endpoint"),
          statusForAdminError("not_found"),
        );
      }
      endpointId = endpoint.id;
    }

    let after: AuditEventCursor | undefined;
    if (query.cursor !== undefined) {
      after = decodeAuditCursor(query.cursor);
      if (after === undefined) {
        return c.json(
          adminErrorBody("invalid_request", "That paging cursor is not valid"),
          statusForAdminError("invalid_request"),
        );
      }
    }

    const page = await withTenantScope(context.db, scope, (bound) =>
      queryAuditEvents(bound, {
        ...(endpointId === undefined ? {} : { endpointId }),
        ...(query.actorType === undefined
          ? {}
          : { actorType: query.actorType }),
        ...(query.actorId === undefined ? {} : { actorId: query.actorId }),
        ...(actions.length === 0 ? {} : { actions }),
        ...(targetType === undefined ? {} : { targetType }),
        ...(query.targetId === undefined ? {} : { targetId: query.targetId }),
        ...(query.from === undefined ? {} : { from: query.from }),
        ...(query.until === undefined ? {} : { until: query.until }),
        ...(query.limit === undefined ? {} : { limit: query.limit }),
        ...(after === undefined ? {} : { after }),
        ...(query.order === undefined ? {} : { order: query.order }),
      }),
    );

    return c.json({
      events: page.events.map(auditEventView),
      nextCursor:
        page.nextCursor === null ? null : encodeAuditCursor(page.nextCursor),
    });
  });
}
