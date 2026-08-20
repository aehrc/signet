/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Token introspection (RFC 7662), with SMART's launch-context additions.
 *
 * The endpoint is authenticated: RFC 7662 §2.1 requires it, and an unauthenticated
 * introspection endpoint is a free oracle for testing whether a stolen token is
 * still live. Signet accepts the same three client authentication methods as the
 * token endpoint, and any registered active client may introspect.
 *
 * Nothing here decides whether a token is active. That judgement is made by
 * `@signet/core` from the stored timestamps, in one place against one clock, and
 * this handler only supplies the row. The important consequence: an expired token
 * and a revoked one both introspect as `active: false` with no further detail -
 * RFC 7662 §2.2 requires exactly that, because the difference is information the
 * caller has no right to.
 *
 * A token this endpoint has never issued also answers `active: false` rather than
 * an error. An error would distinguish a forged `jti` from an expired one.
 *
 * Author: John Grimes
 */

import { buildIntrospectionResponse } from "@signet/core";
import { introspectAccessToken, withTenantScope } from "@signet/db";

import { readTokenRequest } from "./authenticatedEndpoint.js";
import { unverifiedTokenIdentifier } from "./tokenIdentifier.js";
import { requestMetadata } from "../http/requestMeta.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { Context } from "hono";

/** The `active: false` answer, which is the same for every negative case. */
const INACTIVE = { active: false } as const;

/* jscpd:ignore-start */
// The preamble below is intentionally identical to the revocation endpoint's: both
// must accept exactly the same credentials, and `readTokenRequest` is the single
// place that decides what those are. Two call sites of one function is the smallest
// this can be.
/**
 * Handles `POST` on the introspection endpoint.
 *
 * @param context - The server's dependencies.
 */
export function introspectHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const issuerContext = c.get("issuer");
    const metadata = requestMetadata(c);

    const request = await readTokenRequest(c, context);
    if (request instanceof Response) {
      return request;
    }

    /* jscpd:ignore-end */

    const jti = unverifiedTokenIdentifier(request.token);
    if (jti === undefined) {
      return c.json(INACTIVE);
    }

    const record = await withTenantScope(
      context.db,
      issuerContext.scope,
      (bound) => introspectAccessToken(bound, jti),
    );
    if (record === undefined) {
      return c.json(INACTIVE);
    }

    await context.audit.record(context.db, {
      tenantId: issuerContext.tenant.id,
      endpointId: issuerContext.endpoint.id,
      endpointSlug: issuerContext.endpoint.slug,
      actor: { type: "client", id: request.authenticated.client.clientId },
      action: "token.introspected",
      target: { type: "access-token", id: jti },
      detail: { subject: record.subject },
      ...metadata,
    });

    c.header("Cache-Control", "no-store");
    return c.json(
      buildIntrospectionResponse(
        record,
        Math.floor(context.clock().getTime() / 1000),
      ),
    );
  };
}
