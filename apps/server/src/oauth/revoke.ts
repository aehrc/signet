/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Token revocation (RFC 7009).
 *
 * Two properties of this endpoint are counterintuitive and both are required.
 *
 * It answers 200 whether or not anything was revoked. RFC 7009 §2.2 says an
 * invalid token does not cause an error response, and the reason is the same as for
 * introspection: distinguishing "revoked it" from "never heard of it" would tell a
 * caller holding a guessed token whether the guess was right.
 *
 * Revoking a refresh token revokes its whole rotation family, not just the row
 * presented. A family is one authorization, and the tokens in it are successive
 * names for the same grant - revoking only the leaf would leave a rotated
 * predecessor's successor live, which is not what "revoke my access" means.
 *
 * `token_type_hint` is honoured as a hint and no more. RFC 7009 §2.1 requires the
 * server to try the other type if the hint does not match, and a client that sends
 * the wrong hint should not be quietly left with a live token.
 *
 * Author: John Grimes
 */

import {
  findRefreshToken,
  hashToken,
  revokeAccessToken,
  revokeRefreshTokenFamily,
  withTenantScope,
} from "@signet/db";

import { readTokenRequest } from "./authenticatedEndpoint.js";
import { requestMetadata } from "../http/requestMeta.js";
import { formField } from "./grants/index.js";
import { unverifiedTokenIdentifier } from "./tokenIdentifier.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { Context } from "hono";

/* jscpd:ignore-start */
// The preamble below is intentionally identical to the introspection endpoint's: both
// must accept exactly the same credentials, and `readTokenRequest` is the single
// place that decides what those are. Two call sites of one function is the smallest
// this can be.
/**
 * Handles `POST` on the revocation endpoint.
 *
 * @param context - The server's dependencies.
 */
export function revokeHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const issuerContext = c.get("issuer");
    const metadata = requestMetadata(c);

    const request = await readTokenRequest(c, context);
    if (request instanceof Response) {
      return request;
    }
    /* jscpd:ignore-end */

    const { scope, client } = request.authenticated;
    const token = request.token;
    const hint = formField(request.body, "token_type_hint");

    const now = context.clock();
    let revoked: "access-token" | "refresh-token" | "nothing" = "nothing";

    /** Tries to revoke the value as a refresh token, family and all. */
    const tryRefresh = async (): Promise<boolean> => {
      const held = await withTenantScope(
        context.db,
        issuerContext.scope,
        async (bound) => findRefreshToken(bound, await hashToken(token)),
      );
      // A client may only revoke its own tokens. Presenting somebody else's is
      // answered as though nothing matched, which is both what RFC 7009 §2.1
      // permits and the only answer that reveals nothing.
      if (held === undefined || held.clientId !== scope.clientRowId) {
        return false;
      }
      await withTenantScope(context.db, issuerContext.scope, (bound) =>
        revokeRefreshTokenFamily(bound, held.familyId, now),
      );
      return true;
    };

    /** Tries to revoke the value as an access token. */
    const tryAccess = async (): Promise<boolean> => {
      const jti = unverifiedTokenIdentifier(token);
      if (jti === undefined) {
        return false;
      }
      return await withTenantScope(context.db, issuerContext.scope, (bound) =>
        revokeAccessToken(bound, jti, now),
      );
    };

    // The hint decides which is tried first, never which is tried at all: RFC 7009
    // §2.1 requires the other type to be attempted when the hint does not match, and
    // a client that sends the wrong hint must not be left holding a live token.
    if (hint === "refresh_token") {
      if (await tryRefresh()) {
        revoked = "refresh-token";
      } else if (await tryAccess()) {
        revoked = "access-token";
      }
    } else if (await tryAccess()) {
      revoked = "access-token";
    } else if (await tryRefresh()) {
      revoked = "refresh-token";
    }

    if (revoked !== "nothing") {
      await context.audit.record(context.db, {
        tenantId: issuerContext.tenant.id,
        endpointId: issuerContext.endpoint.id,
        endpointSlug: issuerContext.endpoint.slug,
        actor: { type: "client", id: client.clientId },
        action: "token.revoked",
        target: { type: revoked },
        detail: { reason: "client-request", credentialKind: revoked },
        ...metadata,
      });
    }

    // 200 either way. See the module header.
    c.header("Cache-Control", "no-store");
    return c.body(null, 200);
  };
}
