/**
 * Postgres enum types for every closed value set in the Signet data model.
 *
 * These are real database enums rather than check-constrained text so that
 * adding a value is a visible migration. Several of them mirror a union in
 * `@signet/core`; `schema.test.ts` asserts the two never drift, because a
 * mismatch would only surface as a runtime cast failure deep inside a grant
 * handler.
 */

import { pgEnum } from "drizzle-orm/pg-core";

/** A member's authority within a tenant. Also used for API token scoping. */
export const tenantMemberRoleEnum = pgEnum("tenant_member_role", [
  "owner",
  "admin",
  "developer",
  "viewer",
]);

/** How end users authenticate on an endpoint. */
export const endpointAuthModeEnum = pgEnum("endpoint_auth_mode", [
  "local",
  "persona",
  "oidc",
]);

/** How much consent an endpoint asks the end user for. */
export const endpointConsentModeEnum = pgEnum("endpoint_consent_mode", [
  "always",
  "remember",
  "auto",
]);

/** Whether an endpoint will serve authorization requests. */
export const endpointStatusEnum = pgEnum("endpoint_status", [
  "active",
  "disabled",
]);

/**
 * Signing algorithms for endpoint keys.
 *
 * SMART requires RS384 or ES384 for `private_key_jwt`, and Signet signs its own
 * tokens with the same set so that a resource server needs no special casing.
 */
export const endpointKeyAlgorithmEnum = pgEnum("endpoint_key_algorithm", [
  "RS384",
  "ES384",
]);

/**
 * Rotation state of an endpoint signing key.
 *
 * `active` signs; `next` is published in JWKS ahead of promotion so relying
 * parties have cached it before it is first used; `retired` is kept only long
 * enough for tokens it signed to expire.
 */
export const endpointKeyStatusEnum = pgEnum("endpoint_key_status", [
  "active",
  "next",
  "retired",
]);

/** Client authentication posture. Mirrors `ClientType` in `@signet/core`. */
export const clientTypeEnum = pgEnum("client_type", [
  "public",
  "confidential-symmetric",
  "confidential-asymmetric",
]);

/** Registration lifecycle of a client. Only `active` may obtain a token. */
export const clientStatusEnum = pgEnum("client_status", [
  "pending",
  "active",
  "suspended",
  "rejected",
]);

/** Review state of a self-serve client registration request. */
export const clientRequestStatusEnum = pgEnum("client_request_status", [
  "pending",
  "approved",
  "rejected",
]);

/** OAuth grants Signet implements. Mirrors `GrantType` in `@signet/core`. */
export const grantTypeEnum = pgEnum("grant_type", [
  "authorization_code",
  "client_credentials",
  "refresh_token",
]);

/**
 * What kind of principal caused an audit event.
 *
 * `system` covers scheduled work such as expiry sweeps and key promotion, which
 * still has to be attributable.
 */
export const auditActorTypeEnum = pgEnum("audit_actor_type", [
  "admin_user",
  "api_token",
  "end_user",
  "client",
  "system",
]);
