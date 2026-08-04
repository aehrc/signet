/**
 * The preamble the introspection and revocation endpoints share.
 *
 * Both are authenticated with the same three client authentication methods as the
 * token endpoint - RFC 7662 §2.1 requires it for introspection, and an
 * unauthenticated one of either is a free oracle for testing whether a stolen token
 * is still live. Both then read a `token` parameter out of the same form body.
 *
 * Factoring it out is not only about repetition. The two endpoints must accept
 * exactly* the same credentials: an operator who can revoke a token but cannot
 * introspect it, or the reverse, has a surprise waiting, and two copies of this
 * sequence is how that happens.
 *
 * Author: John Grimes
 */

import {
  authenticateClient,
  credentialFieldsFrom,
} from "./clientAuthentication.js";
import { oauthErrorBody, statusForTokenError } from "../http/oauthErrors.js";
import { formField } from "./grants/index.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { AuthenticatedClient } from "./clientAuthentication.js";
import type { FormBody } from "./grants/types.js";
import type { Context } from "hono";

/** A request that named a token and proved which client is asking about it. */
export interface TokenIntrospectionRequest {
  readonly authenticated: AuthenticatedClient;
  /** The `token` parameter, verbatim. May be anything at all. */
  readonly token: string;
  readonly body: FormBody;
}

/**
 * Authenticates the caller and reads the `token` parameter.
 *
 * @returns The request, or the response to send instead. Returning the response
 *   rather than throwing keeps the status and body decisions in one place, where the
 *   two endpoints cannot drift apart.
 */
export async function readTokenRequest(
  c: Context<SignetEnvironment>,
  context: ServerContext,
): Promise<TokenIntrospectionRequest | Response> {
  const issuerContext = c.get("issuer");
  const body = await c.req.parseBody();

  const authentication = await authenticateClient(
    context,
    issuerContext,
    c.req.header("authorization"),
    credentialFieldsFrom(body),
  );
  if (!authentication.ok) {
    return c.json(
      oauthErrorBody(authentication.code, authentication.description),
      statusForTokenError(authentication.code),
    );
  }

  const token = formField(body, "token");
  if (token === undefined) {
    return c.json(oauthErrorBody("invalid_request", "token is required"), 400);
  }

  return { authenticated: authentication.authenticated, token, body };
}
