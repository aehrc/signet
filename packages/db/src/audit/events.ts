/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The closed vocabulary of everything Signet records in its audit log.
 *
 * Actions are a union rather than free-text strings because an audit log is only
 * useful if it can be reviewed: a reviewer has to be able to enumerate what the
 * system can possibly claim happened, and a filter on `action` has to be a
 * select rather than a text box. A typo in a free-text action name produces an
 * event that no filter will ever surface, which is indistinguishable from the
 * event never having been recorded.
 *
 * Adding an action means adding it here, which forces a description and a
 * category through the exhaustive `Record` types below.
 *
 * Author: John Grimes
 */

import type { auditActorTypeEnum } from "../schema/enums.js";

/** What kind of principal caused an event. */
export type AuditActorType =
  "admin-user" | "end-user" | "client" | "api-token" | "system";

/**
 * The `audit_actor_type` Postgres enum's value set.
 *
 * The database spells these with underscores and the domain spells them with
 * hyphens, matching how every other identifier crosses that boundary in Signet
 * (`confidential-symmetric`, `authorization_code`). The two are mapped
 * explicitly below rather than transformed with a regular expression, so a
 * divergence is a compile error rather than a silently mis-stored actor.
 */
export type AuditActorTypeColumn =
  (typeof auditActorTypeEnum.enumValues)[number];

/** Maps a domain actor type onto the value stored in the column. */
export const AUDIT_ACTOR_TYPE_TO_COLUMN: Readonly<
  Record<AuditActorType, AuditActorTypeColumn>
> = {
  "admin-user": "admin_user",
  "end-user": "end_user",
  client: "client",
  "api-token": "api_token",
  system: "system",
};

/** Maps a stored actor type back onto the domain union. */
export const AUDIT_ACTOR_TYPE_FROM_COLUMN: Readonly<
  Record<AuditActorTypeColumn, AuditActorType>
> = {
  admin_user: "admin-user",
  end_user: "end-user",
  client: "client",
  api_token: "api-token",
  system: "system",
};

/** Every domain actor type, in a stable order for rendering a filter. */
export const AUDIT_ACTOR_TYPES: readonly AuditActorType[] = Object.keys(
  AUDIT_ACTOR_TYPE_TO_COLUMN,
) as AuditActorType[];

/**
 * Broad grouping used by the console's audit browser.
 *
 * Deliberately coarse: an operator asking "who has been changing my
 * configuration?" should not have to know which of thirty action names counts.
 */
export type AuditActionCategory =
  "authentication" | "authorization" | "configuration";

/**
 * Every action Signet can record.
 *
 * Names are `subject.verb-in-past-tense`, with the subject naming the thing
 * acted upon rather than the actor - the actor is a separate column, and the
 * same action can be taken by an admin user, an API token or the system.
 */
export type AuditAction =
  // Authentication.
  | "admin.login"
  | "admin.login-failed"
  | "admin.logout"
  | "admin.password-changed"
  | "admin.totp-enabled"
  | "admin.totp-disabled"
  | "admin.passkey-registered"
  | "admin.passkey-removed"
  | "end-user.login"
  | "end-user.login-failed"
  // Authorization.
  | "authorize.requested"
  | "authorize.denied"
  | "authorize.consented"
  | "authorize.code-issued"
  | "token.issued"
  | "token.denied"
  | "token.refreshed"
  | "token.refresh-reuse-detected"
  | "token.jti-replay-detected"
  | "token.ticket-exchanged"
  | "token.revoked"
  | "token.introspected"
  | "consent.granted"
  | "consent.revoked"
  | "launch-context.created"
  | "launch-context.consumed"
  // Configuration.
  | "tenant.created"
  | "tenant.updated"
  | "tenant-member.added"
  | "tenant-member.removed"
  | "tenant-member.role-changed"
  | "api-token.created"
  | "api-token.revoked"
  | "endpoint.created"
  | "endpoint.updated"
  | "endpoint.deleted"
  | "key.created"
  | "key.rotated"
  | "key.retired"
  | "idp-config.created"
  | "idp-config.updated"
  | "idp-config.deleted"
  | "policy.created"
  | "policy.published"
  | "client.created"
  | "client.updated"
  | "client.suspended"
  | "client.deleted"
  | "client.secret-rotated"
  | "client.registration-attempted"
  | "trust-anchor.configured"
  | "trust-anchor.removed"
  | "ticket-issuer.configured"
  | "ticket-issuer.removed"
  | "client-request.submitted"
  | "client-request.approved"
  | "client-request.rejected"
  | "end-user.created"
  | "end-user.updated"
  | "end-user.disabled";

/**
 * Human-readable description of each action.
 *
 * Exported so the console's audit browser renders an event without restating the
 * vocabulary in the UI layer, where it would drift. Written from the reader's
 * point of view, in the past tense, without naming the actor.
 */
export const AUDIT_ACTION_DESCRIPTIONS: Readonly<Record<AuditAction, string>> =
  {
    "admin.login": "Administrator signed in to the console",
    "admin.login-failed": "Administrator sign-in was refused",
    "admin.logout": "Administrator signed out",
    "admin.password-changed": "Administrator password was changed",
    "admin.totp-enabled": "Two-factor authentication was enabled",
    "admin.totp-disabled": "Two-factor authentication was disabled",
    "admin.passkey-registered":
      "Passkey registered on an administrator account",
    "admin.passkey-removed": "Passkey removed from an administrator account",
    "end-user.login": "End user signed in on an endpoint",
    "end-user.login-failed": "End user sign-in was refused",

    "authorize.requested": "Authorization request received",
    "authorize.denied": "Authorization request refused",
    "authorize.consented": "End user consented to the requested scopes",
    "authorize.code-issued": "Authorization code issued",
    "token.issued": "Access token issued",
    "token.denied": "Token request refused",
    "token.refreshed": "Access token reissued from a refresh token",
    "token.refresh-reuse-detected":
      "A refresh token was replayed; the whole token family was revoked",
    "token.jti-replay-detected":
      "A client assertion identifier was replayed and rejected",
    "token.ticket-exchanged":
      "A permission ticket was presented at the token endpoint and exchanged, or refused",
    "token.revoked": "Token revoked",
    "token.introspected": "Token introspected",
    "consent.granted": "Consent recorded for later reuse",
    "consent.revoked": "Stored consent withdrawn",
    "launch-context.created": "Launch context handle minted",
    "launch-context.consumed": "Launch context handle redeemed",

    "tenant.created": "Tenant created",
    "tenant.updated": "Tenant settings changed",
    "tenant-member.added": "Member added to the tenant",
    "tenant-member.removed": "Member removed from the tenant",
    "tenant-member.role-changed": "Member's role within the tenant changed",
    "api-token.created": "Personal access token created",
    "api-token.revoked": "Personal access token revoked",
    "endpoint.created": "Endpoint created",
    "endpoint.updated": "Endpoint configuration changed",
    "endpoint.deleted": "Endpoint deleted",
    "key.created": "Signing key created",
    "key.rotated": "Signing key promoted to active",
    "key.retired": "Signing key retired",
    "idp-config.created": "Upstream identity provider configured",
    "idp-config.updated": "Upstream identity provider configuration changed",
    "idp-config.deleted": "Upstream identity provider removed",
    "policy.created": "Policy version created",
    "policy.published": "Policy version published",
    "client.created": "Client registered",
    "client.updated": "Client registration changed",
    "client.suspended": "Client suspended",
    "client.deleted": "Client deleted",
    "client.secret-rotated": "Client secret rotated",
    "client.registration-attempted":
      "Dynamic client registration attempted with a trust anchor's software statement",
    "trust-anchor.configured":
      "Trust anchor configured on an endpoint, enabling vouched registration",
    "trust-anchor.removed":
      "Trust anchor removed from an endpoint, refusing further registrations",
    "ticket-issuer.configured":
      "Permission ticket issuer configured on an endpoint, enabling token exchange",
    "ticket-issuer.removed":
      "Permission ticket issuer removed from an endpoint, refusing further exchanges",
    "client-request.submitted": "Client registration requested by a developer",
    "client-request.approved": "Client registration request approved",
    "client-request.rejected": "Client registration request rejected",
    "end-user.created": "End user created",
    "end-user.updated": "End user changed",
    "end-user.disabled": "End user disabled",
  };

/** Which broad group each action belongs to. */
export const AUDIT_ACTION_CATEGORIES: Readonly<
  Record<AuditAction, AuditActionCategory>
> = {
  "admin.login": "authentication",
  "admin.login-failed": "authentication",
  "admin.logout": "authentication",
  "admin.password-changed": "authentication",
  "admin.totp-enabled": "authentication",
  "admin.totp-disabled": "authentication",
  "admin.passkey-registered": "authentication",
  "admin.passkey-removed": "authentication",
  "end-user.login": "authentication",
  "end-user.login-failed": "authentication",

  "authorize.requested": "authorization",
  "authorize.denied": "authorization",
  "authorize.consented": "authorization",
  "authorize.code-issued": "authorization",
  "token.issued": "authorization",
  "token.denied": "authorization",
  "token.refreshed": "authorization",
  "token.refresh-reuse-detected": "authorization",
  "token.jti-replay-detected": "authorization",
  "token.ticket-exchanged": "authorization",
  "token.revoked": "authorization",
  "token.introspected": "authorization",
  "consent.granted": "authorization",
  "consent.revoked": "authorization",
  "launch-context.created": "authorization",
  "launch-context.consumed": "authorization",

  "tenant.created": "configuration",
  "tenant.updated": "configuration",
  "tenant-member.added": "configuration",
  "tenant-member.removed": "configuration",
  "tenant-member.role-changed": "configuration",
  "api-token.created": "configuration",
  "api-token.revoked": "configuration",
  "endpoint.created": "configuration",
  "endpoint.updated": "configuration",
  "endpoint.deleted": "configuration",
  "key.created": "configuration",
  "key.rotated": "configuration",
  "key.retired": "configuration",
  "idp-config.created": "configuration",
  "idp-config.updated": "configuration",
  "idp-config.deleted": "configuration",
  "policy.created": "configuration",
  "policy.published": "configuration",
  "client.created": "configuration",
  "client.updated": "configuration",
  "client.suspended": "configuration",
  "client.deleted": "configuration",
  "client.secret-rotated": "configuration",
  "client.registration-attempted": "configuration",
  "trust-anchor.configured": "configuration",
  "trust-anchor.removed": "configuration",
  "ticket-issuer.configured": "configuration",
  "ticket-issuer.removed": "configuration",
  "client-request.submitted": "configuration",
  "client-request.approved": "configuration",
  "client-request.rejected": "configuration",
  "end-user.created": "configuration",
  "end-user.updated": "configuration",
  "end-user.disabled": "configuration",
};

/**
 * Every action, derived from the description map rather than listed again.
 *
 * Deriving it means the runtime list and the descriptions cannot disagree.
 */
export const AUDIT_ACTIONS: readonly AuditAction[] = Object.keys(
  AUDIT_ACTION_DESCRIPTIONS,
) as AuditAction[];

const AUDIT_ACTION_SET: ReadonlySet<string> = new Set(AUDIT_ACTIONS);

/**
 * Narrows an arbitrary string to an action Signet knows about.
 *
 * Read paths need this because `audit_events.action` is a text column: a row
 * written by a newer deployment during a rolling upgrade can name an action this
 * process has never heard of, and an audit browser must still render it.
 *
 * @param value - Candidate action name.
 */
export function isAuditAction(value: string): value is AuditAction {
  return AUDIT_ACTION_SET.has(value);
}

/**
 * What an event was done to.
 *
 * Closed for the same reason actions are: `target_type` is indexed and filtered
 * on, so an unenumerated value is an event nobody will find.
 */
export type AuditTargetType =
  | "tenant"
  | "tenant-member"
  | "admin-user"
  | "admin-passkey"
  | "api-token"
  | "endpoint"
  | "endpoint-key"
  | "idp-config"
  | "trust-anchor"
  | "ticket-issuer"
  | "end-user"
  | "client"
  | "client-request"
  | "policy"
  | "consent"
  | "launch-context"
  | "authorization-session"
  | "authorization-code"
  | "access-token"
  | "refresh-token";

/**
 * Every target type, as a runtime value.
 *
 * Written as an exhaustive `Record` so that adding a member to the union without
 * adding it here is a compile error. The console's audit browser filters on this,
 * and a target type missing from the list would be a filter nobody could select.
 */
const AUDIT_TARGET_TYPE_SET: Readonly<Record<AuditTargetType, true>> = {
  tenant: true,
  "tenant-member": true,
  "admin-user": true,
  "admin-passkey": true,
  "api-token": true,
  endpoint: true,
  "endpoint-key": true,
  "idp-config": true,
  "trust-anchor": true,
  "ticket-issuer": true,
  "end-user": true,
  client: true,
  "client-request": true,
  policy: true,
  consent: true,
  "launch-context": true,
  "authorization-session": true,
  "authorization-code": true,
  "access-token": true,
  "refresh-token": true,
};

/** Every kind of thing an event can be recorded against. */
export const AUDIT_TARGET_TYPES: readonly AuditTargetType[] = Object.keys(
  AUDIT_TARGET_TYPE_SET,
) as AuditTargetType[];

/**
 * Narrows an arbitrary string to a target type this deployment knows about.
 *
 * Needed on the read path for the same reason {@link isAuditAction} is: the column
 * is text, so a row written by a newer deployment can name a target type this
 * process has never heard of, and a filter arriving from a query string is
 * untrusted either way.
 *
 * @param value - Candidate target type.
 */
export function isAuditTargetType(value: string): value is AuditTargetType {
  return Object.hasOwn(AUDIT_TARGET_TYPE_SET, value);
}

/**
 * The principal responsible for an event.
 *
 * `id` is absent for `system` actors and for a failed sign-in where the
 * identifier offered did not resolve to an account - recording an attacker's
 * guess as though it were an account identifier would be misleading.
 */
export interface AuditActor {
  readonly type: AuditActorType;
  readonly id?: string;
  /**
   * Copied into the detail blob at write time so the row stays readable after
   * the referent is deleted. `actor_id` carries no foreign key precisely so that
   * deletions cannot truncate the trail, which means nothing else can resolve
   * the name later.
   */
  readonly displayName?: string;
}

/** The thing an event was done to. */
export interface AuditTarget {
  readonly type: AuditTargetType;
  readonly id?: string;
}

/** One recordable event. */
export interface AuditEventInput {
  /** Owning tenant. Every event belongs to exactly one. */
  readonly tenantId: string;
  /** Endpoint the event happened on, where the action is endpoint-scoped. */
  readonly endpointId?: string;
  /**
   * Endpoint slug, echoed into the detail blob. The endpoint row can be deleted
   * (which nulls `endpoint_id`) or renamed, and the trail must still say which
   * endpoint this was at the time.
   */
  readonly endpointSlug?: string;
  readonly actor: AuditActor;
  readonly action: AuditAction;
  readonly target?: AuditTarget;
  /**
   * Anything specific to this action.
   *
   * Typed `unknown` rather than a record because call sites pass through
   * request-shaped data, and pretending it is already well formed would push a
   * cast into every one of them. It is normalised and stripped of credentials by
   * `redactAuditDetail` on the way in - see `record.ts`.
   */
  readonly detail?: unknown;
  readonly ip?: string;
  readonly userAgent?: string;
  /**
   * Occurrence time. Omit to let Postgres stamp it, which is what production
   * should do: one clock for the whole log means events sort correctly no matter
   * which process wrote them.
   */
  readonly at?: Date;
}

/** An audit event as read back, with database spellings mapped to the domain. */
export interface AuditEventRecord {
  readonly id: string;
  readonly tenantId: string;
  readonly endpointId: string | null;
  readonly actorType: AuditActorType;
  readonly actorId: string | null;
  /**
   * The recorded action.
   *
   * Typed as the union because `recordAuditEvent` is the only writer and it
   * accepts nothing else. Use `isAuditAction` before looking the value up in
   * `AUDIT_ACTION_DESCRIPTIONS` if the caller must tolerate a row written by a
   * newer deployment.
   */
  readonly action: AuditAction;
  readonly targetType: string | null;
  readonly targetId: string | null;
  readonly detail: Record<string, unknown>;
  readonly ip: string | null;
  readonly userAgent: string | null;
  readonly at: Date;
}
