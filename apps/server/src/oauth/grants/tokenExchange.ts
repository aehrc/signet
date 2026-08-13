/**
 * The RFC 8693 token exchange grant, for a SMART permission ticket.
 *
 * A ticket is a third party's assertion that some patient has permitted some
 * access to their record on this endpoint's FHIR server. Exchanging one produces
 * an ordinary SMART access token - the same claims, the same patient launch
 * context, the same policy - so that a resource server cannot tell an exchanged
 * token from one the patient obtained by launching the app, other than by who its
 * subject is.
 *
 * ## The order the checks run in, and why it is that order
 *
 * 1. **The rule, before anything else this grant does.** An endpoint with no
 *    ticket issuer refuses the grant type outright and advertises no ticket
 *    support, and nothing is parsed, fetched or resolved before the rule has been
 *    found. In particular the endpoint's FHIR server is never searched: an
 *    endpoint that has not opted in must not be made to look a patient up by
 *    anybody who can post a ticket at it.
 * 2. **The client's own posture.** The token endpoint has already authenticated
 *    whoever called, which is where an unknown client or a bad secret is refused.
 *    What is left for this grant is the posture: a public client authenticates
 *    with nothing, and a ticket naming a patient is not presented by a caller
 *    whose identity the endpoint cannot verify.
 * 3. **The request shape.** A `subject_token`, presented as a JWT. RFC 8693 lets
 *    a subject token be several things, and reading an access token as though it
 *    were a ticket would accept a credential the issuer never minted for this.
 * 4. **The signature**, against keys fetched through the outbound guard, and then
 *    the claims: the issuer named by the rule, within validity, of a type the
 *    rule accepts.
 * 5. **The subject**, resolved to exactly one patient by searching the endpoint's
 *    own FHIR server. Zero refuses and so does more than one.
 * 6. **The intersection**, of what was asked for, what the ticket permits and
 *    what this client's registration allows - and then, inside the issuance
 *    chokepoint, of what the endpoint's policy grants. An empty result refuses
 *    rather than minting a scopeless token.
 *
 * The exchanged token is evaluated as an `authorization_code` grant, and
 * deliberately: what the ticket authorises is a patient-context session, and
 * asking the policy a different question would produce a token whose claims
 * differ from the interactive launch it is meant to be indistinguishable from.
 * The ticket is what bounds it, not a grant type nobody has written a rule for.
 *
 * Every attempt is audited as `token.ticket-exchanged` with the ticket's
 * identifier and the outcome, and never the ticket: a ticket is a bearer
 * credential naming a patient.
 *
 * Author: John Grimes
 */

import {
  ACCESS_TOKEN_TYPE,
  capExchangedTokenLifetime,
  intersectTicketScopes,
  JWT_SUBJECT_TOKEN_TYPE,
  parseScopes,
  PERMITTED_TICKET_ALGORITHMS,
  validatePermissionTicket,
} from "@signet/core";
import {
  getEndpointTicketIssuer,
  toEvaluationClient,
  withTenantScope,
} from "@signet/db";

import { recordTicketExchange } from "./audit.js";
import { issuanceRefusalOutcome } from "./issuanceRefusals.js";
import { issueTokens } from "../issuance.js";
import { resolveTicketSubject } from "../subjectResolution.js";
import { verifyTrustedJws } from "../trustedJws.js";
import { formField, grantRefusal } from "./types.js";

import type { ExchangeAudit } from "./audit.js";
import type { GrantOutcome, GrantRequest } from "./types.js";
import type { ServerContext } from "../../context.js";
import type { ValidatedTicket } from "@signet/core";

/**
 * Exchanges a permission ticket for an access token.
 *
 * @param context - The server's dependencies.
 * @param request - The authenticated client and the request body.
 * @returns The token response, or the refusal for the token endpoint to audit
 *   and return.
 */
export async function tokenExchangeGrant(
  context: ServerContext,
  request: GrantRequest,
): Promise<GrantOutcome> {
  const { issuerContext, authenticated, body } = request;
  const { scope, client } = authenticated;

  const rule = await withTenantScope(context.db, issuerContext.scope, (bound) =>
    getEndpointTicketIssuer(bound),
  );
  if (rule === undefined) {
    // Indistinguishable from a grant type this server does not implement, which
    // is what an endpoint with no rule must look like. Not audited as an
    // exchange: no ticket has been read, and there is nothing to record one by.
    return grantRefusal(
      "unsupported_grant_type",
      `grant_type ${String(formField(body, "grant_type"))} is not supported`,
    );
  }

  /** Refuses, with the reason in the audit trail and in the response. */
  const refuse = async (
    code: Parameters<typeof grantRefusal>[0],
    description: string,
    detail: Omit<ExchangeAudit, "outcome"> = {},
  ): Promise<GrantOutcome> => {
    await recordTicketExchange(context, request, {
      outcome: "refused",
      error: code,
      description,
      ...detail,
    });
    return grantRefusal(code, description, {
      reason: "ticket-exchange",
      ...(detail.ticketId === undefined ? {} : { ticketId: detail.ticketId }),
    });
  };

  if (authenticated.method === "none") {
    // A public client authenticates with nothing. RFC 6749 §5.2 makes this
    // `invalid_client`, which is a 401 here: the caller has to come back as a
    // client this endpoint can verify, not ask for less.
    return await refuse(
      "invalid_client",
      "A permission ticket is exchanged only by a client that authenticates",
    );
  }

  const subjectToken = formField(body, "subject_token");
  if (subjectToken === undefined) {
    return await refuse("invalid_request", "subject_token is required");
  }
  const subjectTokenType = formField(body, "subject_token_type");
  if (subjectTokenType !== JWT_SUBJECT_TOKEN_TYPE) {
    return await refuse(
      "invalid_request",
      `subject_token_type must be ${JWT_SUBJECT_TOKEN_TYPE}`,
    );
  }

  const verified = await verifyTrustedJws(context, {
    jwksUri: rule.jwksUri,
    token: subjectToken,
    algorithms: PERMITTED_TICKET_ALGORITHMS,
    noun: "permission ticket",
  });
  if (!verified.ok) {
    return await refuse("invalid_grant", verified.description);
  }

  const validated = validatePermissionTicket({
    claims: verified.claims,
    issuer: rule.issuer,
    acceptedTicketTypes: rule.acceptedTicketTypes,
    now: context.clock(),
  });
  if (!validated.ok) {
    return await refuse("invalid_grant", validated.description);
  }
  const ticket: ValidatedTicket = validated.ticket;
  const identity = {
    ticketId: ticket.ticketId,
    ticketType: ticket.ticketType,
  };

  const resolved = await resolveTicketSubject(context, {
    issuerContext,
    clientScope: scope,
    client: toEvaluationClient(client),
    subject: ticket.subject,
  });
  if (!resolved.ok) {
    return await refuse("invalid_grant", resolved.description, identity);
  }

  const overlap = intersectTicketScopes({
    requested: parseScopes(formField(body, "scope") ?? "").scopes,
    ticketScopes: ticket.scopes,
    clientAllowlist: parseScopes(client.allowedScopes.join(" ")).scopes,
  });
  if (!overlap.ok) {
    return await refuse("invalid_scope", overlap.description, identity);
  }

  const now = context.clock();
  const ceiling = capExchangedTokenLifetime({
    ticketRemainingSeconds: Math.floor(
      (ticket.expiresAt.getTime() - now.getTime()) / 1000,
    ),
    ruleMaxLifetimeSeconds: rule.maxTokenLifetimeSecs,
  });
  if (ceiling <= 0) {
    return await refuse(
      "invalid_grant",
      "The permission ticket has expired",
      identity,
    );
  }

  const issued = await issueTokens(context, {
    issuerContext,
    clientScope: scope,
    client: toEvaluationClient(client),
    // No user: the ticket names a patient, and nobody signed in here.
    user: null,
    grantType: "authorization_code",
    requested: overlap.scopes,
    // Exactly what an interactive launch resolving the same patient would carry,
    // which is what makes the two tokens indistinguishable to a resource server.
    launchContext: { patient: resolved.patientId },
    // The ticket's subject, as this server names it. RFC 8693 §2.2.1: the issued
    // token represents the subject of the token that was exchanged.
    subject: `Patient/${resolved.patientId}`,
    vouchingExpiresAt: client.vouchingExpiresAt,
    accessTokenTtlCeiling: ceiling,
  });

  if (!issued.ok) {
    const outcome = issuanceRefusalOutcome(issued.reason);
    await recordTicketExchange(context, request, {
      outcome: "refused",
      ...identity,
      ...(outcome.ok
        ? {}
        : { error: outcome.code, description: outcome.description }),
    });
    return outcome;
  }

  await recordTicketExchange(
    context,
    request,
    {
      outcome: "exchanged",
      ...identity,
      grantedScopeCount: issued.issued.evaluation.grantedScopes.length,
      patient: resolved.patientId,
    },
    issued.issued.jti,
  );

  return {
    ok: true,
    response: {
      ...issued.issued.response,
      // RFC 8693 §2.2.1 requires it, and requires it to name what was actually
      // issued rather than what was asked for.
      issued_token_type: ACCESS_TOKEN_TYPE,
    },
  };
}
