/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The `client_credentials` grant - SMART Backend Services.
 *
 * No user, no launch context, no consent: a backend service acts as itself, so the
 * token's `sub` is the client id and the only `system/` scopes it can obtain are the
 * ones the policy grants for this grant type. The SMART baseline preset restricts
 * `system/*.rs` to `client_credentials` precisely so that an interactive app cannot
 * reach system-context data by asking nicely.
 *
 * Unlike the other two grants, the requested scopes come from the request body,
 * because there is no earlier step to have recorded them. The client's allowlist is
 * therefore checked here - at `/authorize` it is checked as part of validating the
 * request, and a backend service never visits `/authorize`.
 *
 * A refresh token is never issued. SMART Backend Services says so, and it is the
 * right rule: a client that can mint a fresh assertion whenever it likes has no use
 * for a long-lived credential it would then have to store.
 *
 * Author: John Grimes
 */

import { areScopesCoveredBy, parseScopes } from "@signet/core";
import { toEvaluationClient } from "@signet/db";

import { recordTokenIssued } from "./audit.js";
import { issuanceRefusalOutcome } from "./issuanceRefusals.js";
import { issueTokens } from "../issuance.js";
import { formField, grantRefusal } from "./types.js";

import type { GrantOutcome, GrantRequest } from "./types.js";
import type { ServerContext } from "../../context.js";

/**
 * Issues a token to a backend service.
 *
 * @param context - The server's dependencies.
 * @param request - The authenticated client and the request body.
 */
export async function clientCredentialsGrant(
  context: ServerContext,
  request: GrantRequest,
): Promise<GrantOutcome> {
  const { issuerContext, authenticated, body } = request;
  const { scope, client } = authenticated;

  if (!issuerContext.endpoint.supportsBackendServices) {
    return grantRefusal(
      "unsupported_grant_type",
      "This endpoint does not support SMART Backend Services",
    );
  }
  if (!client.grantTypes.includes("client_credentials")) {
    return grantRefusal(
      "unauthorized_client",
      "This client is not registered for the client_credentials grant",
    );
  }

  const raw = formField(body, "scope");
  if (raw === undefined) {
    return grantRefusal(
      "invalid_scope",
      "scope is required for the client_credentials grant",
    );
  }

  const parsed = parseScopes(raw);
  const firstRejected = parsed.rejected[0];
  if (firstRejected !== undefined) {
    return grantRefusal(
      "invalid_scope",
      `Could not parse scope "${firstRejected.raw}": ${firstRejected.message}`,
    );
  }
  if (parsed.scopes.length === 0) {
    return grantRefusal("invalid_scope", "scope is required");
  }

  // The allowlist check that `/authorize` performs for interactive clients. A
  // backend service never visits `/authorize`, so without this its only ceiling
  // would be the policy - and the allowlist is the per-client ceiling an operator
  // edits, while the policy is shared by the endpoint.
  const allowed = parseScopes(client.allowedScopes.join(" ")).scopes;
  if (!areScopesCoveredBy(parsed.scopes, allowed)) {
    return grantRefusal(
      "invalid_scope",
      "The request includes scopes outside this client's allowlist",
    );
  }

  const issued = await issueTokens(context, {
    issuerContext,
    clientScope: scope,
    client: toEvaluationClient(client),
    user: null,
    grantType: "client_credentials",
    requested: parsed.scopes,
    launchContext: {},
    // The client authenticates as itself, so it is its own subject. RFC 9068 §5
    // makes this explicit for a client-credentials token.
    subject: client.clientId,
    vouchingExpiresAt: client.vouchingExpiresAt,
  });

  if (!issued.ok) {
    return issuanceRefusalOutcome(issued.reason);
  }

  await recordTokenIssued(
    context,
    request,
    "client_credentials",
    client.clientId,
    issued.issued,
  );

  return { ok: true, response: issued.issued.response };
}
