/**
 * Token introspection responses (RFC 7662) with the SMART additions.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7662
 *
 * Author: John Grimes
 */

import { toTokenResponseContext } from "../launch/index.js";

import type { IntrospectableToken, IntrospectionResponse } from "./types.js";

/**
 * The only response an inactive token may produce.
 *
 * RFC 7662 section 2.2 is explicit that an introspection response for a token
 * that is not active must not disclose anything else about it. Returning the
 * scope or subject of a revoked token would let a caller holding a stolen or
 * guessed token learn what it was for.
 *
 * A fresh object is built per call rather than shared, so that a caller
 * decorating one response can never contaminate the next.
 */
function inactive(): IntrospectionResponse {
  return { active: false };
}

/**
 * Builds an introspection response for a stored token.
 *
 * An absent, revoked or expired token all yield exactly `{ active: false }`, so
 * that a caller cannot distinguish "never existed" from "no longer valid" and
 * cannot learn anything about a token it should not hold.
 *
 * @param token - The stored token, or `null` when nothing matched.
 * @param now - The current time as seconds since the epoch. A token whose
 *   expiry has arrived is already inactive.
 * @returns The introspection response body.
 */
export function buildIntrospectionResponse(
  token: IntrospectableToken | null,
  now: number,
): IntrospectionResponse {
  if (token === null || token.revokedAt !== null || now >= token.expiresAt) {
    return inactive();
  }

  return {
    // Both spreads sit underneath the RFC 7662 fields: an ID token carries its
    // own `iss`, `aud`, `sub`, `exp` and `iat`, and those describe the identity
    // assertion rather than the token being introspected.
    ...toTokenResponseContext(token.launchContext),
    ...token.idTokenClaims,
    active: true,
    scope: token.scope,
    client_id: token.clientId,
    exp: token.expiresAt,
    iat: token.issuedAt,
    sub: token.subject,
    aud: token.audience,
    iss: token.issuer,
    token_type: "Bearer",
  };
}
