/**
 * The OpenID Connect UserInfo endpoint.
 *
 * Presented with an access token, it returns the identity claims that token's
 * authorization released. What it does *not* do is decide those claims afresh: they
 * come from the `id_token_claims` recorded when the token was issued, so UserInfo
 * and the ID token cannot disagree, and a policy edited since issuance cannot
 * retroactively change what a live token says about its subject.
 *
 * Access is gated on the token, not on the client. A bearer token presented here
 * must be active and must carry the `openid` scope - an access token minted for a
 * backend service with no user has no identity to describe, and answering with the
 * client id as `sub` would invite a caller to treat it as a person.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
 *
 * Author: John Grimes
 */

import { accessTokenState, introspectAccessToken } from "@signet/db";

import { unverifiedTokenIdentifier } from "./tokenIdentifier.js";
import { bearerToken } from "../http/bearer.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { Context } from "hono";

/**
 * Answers RFC 6750 §3 with a `WWW-Authenticate` challenge.
 *
 * The error code is part of the header rather than the body, because a caller that
 * received a 401 has not been given a body it can rely on.
 */
function challenge(
  c: Context<SignetEnvironment>,
  issuer: string,
  error?: "invalid_token",
  description?: string,
) {
  const parts = [`Bearer realm="${issuer}"`];
  if (error !== undefined) {
    parts.push(`error="${error}"`);
  }
  if (description !== undefined) {
    parts.push(`error_description="${description}"`);
  }
  c.header("WWW-Authenticate", parts.join(", "));
  return c.body(null, 401);
}

/**
 * Handles `GET` on the UserInfo endpoint.
 *
 * @param context - The server's dependencies.
 */
export function userinfoHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const issuerContext = c.get("issuer");

    if (!issuerContext.endpoint.supportsOpenIdConnect) {
      return c.json(
        {
          error: "invalid_request",
          error_description: "This endpoint does not support OpenID Connect",
        },
        404,
      );
    }

    const presented = bearerToken(c.req.header("authorization"));
    if (presented === undefined) {
      return challenge(c, issuerContext.issuer);
    }

    const jti = unverifiedTokenIdentifier(presented);
    const record =
      jti === undefined
        ? undefined
        : await introspectAccessToken(context.db, issuerContext.scope, jti);

    if (record === undefined) {
      return challenge(
        c,
        issuerContext.issuer,
        "invalid_token",
        "The access token is not valid",
      );
    }

    const state = accessTokenState(
      {
        revokedAt:
          record.revokedAt === null ? null : new Date(record.revokedAt * 1000),
        expiresAt: new Date(record.expiresAt * 1000),
      },
      context.clock(),
    );
    if (state !== "active") {
      return challenge(
        c,
        issuerContext.issuer,
        "invalid_token",
        `The access token is ${state}`,
      );
    }

    if (record.idTokenClaims === null) {
      // No ID token was issued alongside, which means `openid` was not granted.
      // RFC 6750 §3.1 calls a token lacking the required scope `insufficient_scope`
      // with a 403, and that is the honest answer: the token is valid, and this is
      // not something it may do.
      c.header(
        "WWW-Authenticate",
        `Bearer realm="${issuerContext.issuer}", error="insufficient_scope", scope="openid"`,
      );
      return c.body(null, 403);
    }

    c.header("Cache-Control", "no-store");
    // `sub` is restated from the token record rather than taken from the stored
    // claims, so that the two cannot differ even if a claim rule emitted one.
    return c.json({ ...record.idTokenClaims, sub: record.subject });
  };
}
