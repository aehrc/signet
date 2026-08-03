/**
 * The token endpoint.
 *
 * Client authentication happens once, before the grant is dispatched, because it
 * is the same question for all three grants and because a grant handler that
 * authenticated its own caller would be a grant handler that could forget to.
 * After that, each grant establishes *who* the token is for and *what* was
 * authorised, and hands both to `./issuance.ts`, which is the only place that
 * consults a policy or signs anything.
 *
 * Every refusal is audited as `token.denied` with the reason, and every success as
 * `token.issued` with the policy version that authorised it. That pairing is what
 * makes the audit log able to answer "why does this token contain that claim?" —
 * the answer is a policy version, and policy versions are immutable rows.
 */

import {
  authenticateClient,
  credentialFieldsFrom,
} from "./clientAuthentication.js";
import { oauthErrorBody, statusForTokenError } from "../http/oauthErrors.js";
import { requestMetadata } from "../http/requestMeta.js";
import {
  authorizationCodeGrant,
  clientCredentialsGrant,
  formField,
  refreshTokenGrant,
} from "./grants/index.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { TokenErrorCode } from "../http/oauthErrors.js";
import type { GrantOutcome, GrantRequest } from "./grants/index.js";
import type { Context } from "hono";

/**
 * Handles `POST` on the token endpoint.
 *
 * @param context - The server's dependencies.
 */
export function tokenHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const issuerContext = c.get("issuer");
    const { endpoint, tenant } = issuerContext;
    const metadata = requestMetadata(c);

    const body = await c.req.parseBody();
    const clientId = formField(body, "client_id");
    const grantType = formField(body, "grant_type");

    /** Records a refusal and produces the response. */
    const deny = async (
      code: TokenErrorCode,
      description: string,
      detail: Record<string, unknown> = {},
      status?: 500,
    ) => {
      await context.audit.record(context.db, {
        tenantId: tenant.id,
        endpointId: endpoint.id,
        endpointSlug: endpoint.slug,
        actor: {
          type: "client",
          ...(clientId === undefined ? {} : { id: clientId }),
        },
        action: "token.denied",
        target: { type: "client" },
        detail: { error: code, description, grantType, ...detail },
        ...metadata,
      });
      return c.json(
        oauthErrorBody(code, description),
        status ?? statusForTokenError(code),
      );
    };

    const authorization = c.req.header("authorization");
    const authentication = await authenticateClient(
      context,
      issuerContext,
      authorization,
      credentialFieldsFrom(body),
    );

    if (!authentication.ok) {
      if (authentication.assertionReplayed === true) {
        // A replayed assertion gets its own action. It is the only refusal at this
        // endpoint that is evidence of an attack rather than of a misconfiguration,
        // and an operator should be able to alert on it without matching strings.
        await context.audit.record(context.db, {
          tenantId: tenant.id,
          endpointId: endpoint.id,
          endpointSlug: endpoint.slug,
          actor: {
            type: "client",
            ...(authentication.clientId === undefined
              ? {}
              : { id: authentication.clientId }),
          },
          action: "token.jti-replay-detected",
          target: { type: "client" },
          detail: { clientId: authentication.clientId },
          ...metadata,
        });
      }
      // RFC 6749 §5.2 requires `WWW-Authenticate` when the client tried to
      // authenticate through the header and failed.
      if (
        authentication.code === "invalid_client" &&
        authorization !== undefined
      ) {
        c.header("WWW-Authenticate", `Basic realm="${issuerContext.issuer}"`);
      }
      return await deny(
        authentication.code,
        authentication.description,
        authentication.clientId === undefined
          ? {}
          : { clientId: authentication.clientId },
      );
    }

    const request: GrantRequest = {
      issuerContext,
      authenticated: authentication.authenticated,
      body,
      metadata,
    };

    let outcome: GrantOutcome;
    switch (grantType) {
      case "authorization_code": {
        outcome = await authorizationCodeGrant(context, request);
        break;
      }
      case "client_credentials": {
        outcome = await clientCredentialsGrant(context, request);
        break;
      }
      case "refresh_token": {
        outcome = await refreshTokenGrant(context, request);
        break;
      }
      case undefined: {
        return await deny("invalid_request", "grant_type is required");
      }
      default: {
        return await deny(
          "unsupported_grant_type",
          `grant_type ${grantType} is not supported`,
        );
      }
    }

    if (!outcome.ok) {
      return await deny(
        outcome.code,
        outcome.description,
        outcome.detail ?? {},
        outcome.status,
      );
    }

    // A token response body contains a bearer credential, so it must never be
    // stored by an intermediary. `Pragma` is obsolete but is still honoured by
    // proxies that predate `Cache-Control`.
    c.header("Cache-Control", "no-store");
    c.header("Pragma", "no-cache");
    return c.json(outcome.response);
  };
}
