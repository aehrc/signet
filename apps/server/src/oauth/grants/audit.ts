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
import type { AuditAction, AuditTarget } from "@signet/db";

/**
 * Records one event against the endpoint the grant is running on.
 *
 * The tenant, the endpoint and the actor are the same three fields on every
 * event any grant writes, and writing them out per event meant three copies of
 * the identifiers - three chances for one of them to name the wrong endpoint and
 * for the event to become invisible to the console's filter.
 */
async function recordGrantEvent(
  context: ServerContext,
  request: GrantRequest,
  event: {
    readonly action: AuditAction;
    readonly target: AuditTarget;
    readonly detail: Record<string, unknown>;
  },
): Promise<void> {
  const { issuerContext, authenticated, metadata } = request;
  await context.audit.record(context.db, {
    tenantId: issuerContext.tenant.id,
    endpointId: issuerContext.endpoint.id,
    endpointSlug: issuerContext.endpoint.slug,
    actor: { type: "client", id: authenticated.client.clientId },
    action: event.action,
    target: event.target,
    detail: event.detail,
    ...metadata,
  });
}

/** Records a successful issuance. */
export async function recordTokenIssued(
  context: ServerContext,
  request: GrantRequest,
  grantType: GrantType,
  subject: string,
  issued: IssuedTokens,
): Promise<void> {
  await recordGrantEvent(context, request, {
    action: grantType === "refresh_token" ? "token.refreshed" : "token.issued",
    target: { type: "access-token", id: issued.jti },
    detail: {
      grantType,
      subject,
      scope: issued.grantedScopes,
      policySource: issued.policy.source,
      policyVersion: issued.policy.version,
      clientAuthMethod: request.authenticated.method,
    },
  });
}

/** What the audit trail records about one permission ticket exchange. */
export interface ExchangeAudit {
  readonly outcome: "exchanged" | "refused";
  /** The ticket's `jti`, once it is known. Never the ticket. */
  readonly ticketId?: string;
  readonly ticketType?: string;
  readonly error?: string;
  readonly description?: string;
  readonly grantedScopeCount?: number;
  readonly patient?: string;
}

/**
 * Records one permission ticket exchange attempt.
 *
 * Its own action rather than relying on the token endpoint's `token.denied`,
 * because what an operator reviews an exchange by is the ticket's identifier, and
 * a refusal carrying only an OAuth error code cannot be traced back to the ticket
 * the issuer minted. The ticket itself never appears: it is a bearer credential
 * naming a patient.
 *
 * @param context - The server's dependencies.
 * @param request - The authenticated client and the request being audited.
 * @param detail - The outcome, and the ticket's identity where it is known.
 * @param accessTokenId - The `jti` of the token that was issued, if one was.
 */
export async function recordTicketExchange(
  context: ServerContext,
  request: GrantRequest,
  detail: ExchangeAudit,
  accessTokenId?: string,
): Promise<void> {
  await recordGrantEvent(context, request, {
    action: "token.ticket-exchanged",
    target:
      accessTokenId === undefined
        ? { type: "client", id: request.authenticated.client.clientId }
        : { type: "access-token", id: accessTokenId },
    detail: { ...detail },
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
