/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * What the admin API says about a row.
 *
 * Every response body is built here rather than by returning a row directly, for
 * one reason: several of these tables hold credentials. `clients.secret_hash`,
 * `endpoint_keys.private_jwk_encrypted`, `end_users.password_hash`,
 * `admin_users.totp_secret_encrypted` and `api_tokens.token_hash` must never leave
 * the process, and a handler that spread a row into a response would ship whichever
 * of them it happened to have.
 *
 * So the rule is structural: a response is an explicit projection, and adding a
 * column to the schema does not add it to the API. The cost is that a new field
 * needs an edit here to become visible; the benefit is that a new *secret* cannot
 * become visible without one.
 *
 * Presence is reported instead of value where the console needs to know whether a
 * credential exists - `hasSecret` rather than the secret, `totpEnrolled` rather than
 * the seed.
 *
 * Author: John Grimes
 */

import {
  AUDIT_ACTION_DESCRIPTIONS,
  isAuditAction,
  toCapabilityConfig,
} from "@signet/db";

import type {
  AdminPasskey,
  AdminUser,
  ApiToken,
  AuditEventRecord,
  Client,
  ClientRequest,
  Endpoint,
  EndpointKey,
  EndUser,
  Policy,
  TenantMember,
} from "@signet/db";

/**
 * The capability flags an endpoint advertises.
 *
 * Derived from `toCapabilityConfig` - the same value the discovery documents are
 * built from - rather than enumerated again here. That is what makes it impossible
 * for the console to show a capability set that differs from the one Signet
 * publishes: there is one list, and both readers take it from the same place.
 *
 * The booleans are what a capability is, so the non-boolean members of the config
 * (the issuer, the FHIR base URL, the scope list) are filtered out rather than
 * named - a new flag then appears in the console without an edit, while a new
 * string-valued field does not leak into the capability object.
 *
 * @param endpoint - The endpoint row.
 * @param issuer - The endpoint's issuer, required to build the config.
 */
function capabilityFlags(
  endpoint: Endpoint,
  issuer: string,
): Record<string, boolean> {
  return Object.fromEntries(
    Object.entries(toCapabilityConfig(endpoint, issuer)).filter(
      (entry): entry is [string, boolean] => typeof entry[1] === "boolean",
    ),
  );
}

/** An endpoint, with its issuer and the URLs derived from it. */
export function endpointView(
  endpoint: Endpoint,
  issuer: string,
): Record<string, unknown> {
  return {
    slug: endpoint.slug,
    name: endpoint.name,
    description: endpoint.description,
    fhirBaseUrl: endpoint.fhirBaseUrl,
    issuer,
    /** What an operator pastes into their FHIR server's configuration. */
    smartConfigurationUrl: `${issuer}/.well-known/smart-configuration`,
    status: endpoint.status,
    authMode: endpoint.authMode,
    consentMode: endpoint.consentMode,
    isProduction: endpoint.isProduction,
    accessTokenTtl: endpoint.accessTokenTtl,
    refreshTokenTtl: endpoint.refreshTokenTtl,
    scopesSupported: endpoint.scopesSupported,
    userAccessBrandBundle: endpoint.userAccessBrandBundle,
    userAccessBrandIdentifier: endpoint.userAccessBrandIdentifier,
    capabilities: capabilityFlags(endpoint, issuer),
    createdAt: endpoint.createdAt,
    updatedAt: endpoint.updatedAt,
  };
}

/**
 * A signing key.
 *
 * The public half is included verbatim - it is served from the JWKS anyway - and the
 * private half is not representable here at all.
 */
export function endpointKeyView(key: EndpointKey): Record<string, unknown> {
  return {
    kid: key.kid,
    algorithm: key.algorithm,
    status: key.status,
    publicJwk: key.publicJwk,
    createdAt: key.createdAt,
    activatedAt: key.activatedAt,
    retiredAt: key.retiredAt,
  };
}

/** A registered client. */
export function clientView(client: Client): Record<string, unknown> {
  return {
    clientId: client.clientId,
    name: client.name,
    description: client.description,
    logoUrl: client.logoUrl,
    clientType: client.clientType,
    /** Whether a secret is set, never the secret or its digest. */
    hasSecret: client.secretHash !== null,
    secretExpiresAt: client.secretExpiresAt,
    jwks: client.jwks,
    jwksUri: client.jwksUri,
    jwksCachedAt: client.jwksCachedAt,
    redirectUris: client.redirectUris,
    launchUri: client.launchUri,
    grantTypes: client.grantTypes,
    allowedScopes: client.allowedScopes,
    status: client.status,
    contactEmail: client.contactEmail,
    attributes: client.attributes,
    /**
     * The trust anchor that vouched for this registration, or null.
     *
     * All three or none: the trio is written together at registration and never
     * edited, so a client is vouched exactly when it carries all of them. Sending
     * one object rather than three loose fields keeps the console from having to
     * decide what a half-set means, because it cannot occur.
     */
    vouching:
      client.vouchedByIssuer === null ||
      client.vouchedStatementId === null ||
      client.vouchingExpiresAt === null
        ? null
        : {
            issuer: client.vouchedByIssuer,
            statementId: client.vouchedStatementId,
            expiresAt: client.vouchingExpiresAt,
          },
    createdAt: client.createdAt,
    updatedAt: client.updatedAt,
  };
}

/** An end user or persona. */
export function endUserView(user: EndUser): Record<string, unknown> {
  return {
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    fhirUser: user.fhirUserReference,
    roles: user.roles,
    attributes: user.attributes,
    defaultContext: user.defaultContext,
    isPersona: user.isPersona,
    /** False for a persona by definition; a persona has no password to hold. */
    hasPassword: user.passwordHash !== null,
    disabledAt: user.disabledAt,
    createdAt: user.createdAt,
  };
}

/** A policy version. */
export function policyView(policy: Policy): Record<string, unknown> {
  return {
    version: policy.version,
    document: policy.document,
    note: policy.note,
    published: policy.published,
    createdAt: policy.createdAt,
    createdBy: policy.createdBy,
  };
}

/** A self-serve client registration request. */
export function clientRequestView(
  request: ClientRequest,
): Record<string, unknown> {
  return {
    id: request.id,
    requestedByEmail: request.requestedByEmail,
    payload: request.payload,
    status: request.status,
    decisionNote: request.decisionNote,
    reviewerId: request.reviewerId,
    resultingClientId: request.resultingClientId,
    createdAt: request.createdAt,
    decidedAt: request.decidedAt,
  };
}

/**
 * A personal access token.
 *
 * The digest is a column on the row and is deliberately not projected. It is not a
 * credential, but it is also of no use to a caller, and leaving it out means no
 * response body ever carries anything derived from the token.
 */
export function apiTokenView(token: ApiToken): Record<string, unknown> {
  return {
    id: token.id,
    name: token.name,
    role: token.role,
    createdBy: token.createdBy,
    createdAt: token.createdAt,
    expiresAt: token.expiresAt,
    lastUsedAt: token.lastUsedAt,
    revokedAt: token.revokedAt,
  };
}

/**
 * A registered passkey.
 *
 * Four fields out of nine, and the five left out are the whole reason this file
 * exists. The credential identifier and the public key are not secrets, but they are
 * of no use to the console, and a field a response does not carry is a field a later
 * change cannot start carrying by accident. What the reader needs is enough to
 * recognise the device they are about to remove: its name, when it was added, and
 * when it last let somebody in.
 */
export function passkeyView(passkey: AdminPasskey): Record<string, unknown> {
  return {
    id: passkey.id,
    name: passkey.name,
    createdAt: passkey.createdAt,
    lastUsedAt: passkey.lastUsedAt,
  };
}

/** A tenant membership, with the person's details for display. */
export function memberView(
  member: TenantMember,
  user: AdminUser,
): Record<string, unknown> {
  return {
    adminUserId: member.adminUserId,
    role: member.role,
    email: user.email,
    displayName: user.displayName,
    lastLoginAt: user.lastLoginAt,
    disabledAt: user.disabledAt,
    /** Presence only: the seed is envelope-encrypted and never leaves the process. */
    totpEnrolled: user.totpSecretEncrypted !== null,
  };
}

/**
 * An audit event.
 *
 * The action's description is resolved server-side so the console does not restate
 * the vocabulary - and `isAuditAction` is checked first, because during a rolling
 * upgrade a row may name an action this process has never heard of and the browser
 * must still render it.
 */
export function auditEventView(
  event: AuditEventRecord,
): Record<string, unknown> {
  return {
    id: event.id,
    at: event.at,
    action: event.action,
    description: isAuditAction(event.action)
      ? AUDIT_ACTION_DESCRIPTIONS[event.action]
      : null,
    actorType: event.actorType,
    actorId: event.actorId,
    endpointId: event.endpointId,
    targetType: event.targetType,
    targetId: event.targetId,
    detail: event.detail,
    ip: event.ip,
    userAgent: event.userAgent,
  };
}
