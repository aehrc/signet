/**
 * The audit events every grant writes.
 *
 * All three grants record the same two things - a token was issued, or a presented
 * credential turned out to have been replayed - and the events differ only in the
 * grant name and the subject. Writing them out per grant meant three copies of the
 * tenant and endpoint identifiers, which is three chances for one of them to name
 * the wrong endpoint and for the event to become invisible to the console's filter.
 *
 * The `token.issued` event carries the policy version that authorised the token.
 * That is the field that makes the trail answer "why does this token contain that
 * claim?", and it is only answerable because policy versions are immutable rows.
 *
 * Author: John Grimes
 */

import type { GrantRequest } from "./types.js";
import type { ServerContext } from "../../context.js";
import type { IssuedTokens } from "../issuance.js";
import type { GrantType } from "@signet/core";

/** Records a successful issuance. */
export async function recordTokenIssued(
  context: ServerContext,
  request: GrantRequest,
  grantType: GrantType,
  subject: string,
  issued: IssuedTokens,
): Promise<void> {
  const { issuerContext, authenticated, metadata } = request;
  await context.audit.record(context.db, {
    tenantId: issuerContext.tenant.id,
    endpointId: issuerContext.endpoint.id,
    endpointSlug: issuerContext.endpoint.slug,
    actor: { type: "client", id: authenticated.client.clientId },
    action: grantType === "refresh_token" ? "token.refreshed" : "token.issued",
    target: { type: "access-token", id: issued.jti },
    detail: {
      grantType,
      subject,
      scope: issued.grantedScopes,
      policySource: issued.policy.source,
      policyVersion: issued.policy.version,
      clientAuthMethod: authenticated.method,
    },
    ...metadata,
  });
}

/**
 * Records the revocation that follows a replayed credential.
 *
 * The counts are named without the word "token" on purpose: the audit redactor
 * treats any key containing it as a credential, and a redacted count is a useless
 * one.
 */
export async function recordReplayRevocation(
  context: ServerContext,
  request: GrantRequest,
  event: {
    readonly action: "token.revoked" | "token.refresh-reuse-detected";
    readonly target: "client" | "refresh-token";
    readonly reason?: string;
    readonly revokedAccessCount: number;
    readonly revokedRefreshCount: number;
  },
): Promise<void> {
  const { issuerContext, authenticated, metadata } = request;
  const clientId = authenticated.client.clientId;
  await context.audit.record(context.db, {
    tenantId: issuerContext.tenant.id,
    endpointId: issuerContext.endpoint.id,
    endpointSlug: issuerContext.endpoint.slug,
    actor: { type: "client", id: clientId },
    action: event.action,
    target:
      event.target === "client"
        ? { type: "client", id: clientId }
        : { type: "refresh-token" },
    detail: {
      ...(event.reason === undefined ? {} : { reason: event.reason }),
      revokedAccessCount: event.revokedAccessCount,
      revokedRefreshCount: event.revokedRefreshCount,
    },
    ...metadata,
  });
}
