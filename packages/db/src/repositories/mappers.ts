/**
 * Turning persisted rows into the shapes `@signet/core` evaluates.
 *
 * These are pure total functions, deliberately kept out of the query modules.
 * The domain layer decides what a token contains and what a policy may see; this
 * file is the only place where a column name meets a domain field name, so a
 * schema change that would silently drop a field from a policy's view is a
 * compile error in one small module rather than a subtle behaviour change spread
 * across the grant handlers.
 *
 * Three conversions recur:
 *
 * - `null` becomes an absent property. The database has no way to distinguish
 *   "not set" from "set to nothing", but the core types use optional properties
 *   under `exactOptionalPropertyTypes`, where `{ x: undefined }` and `{}` are
 *   different. Optional fields are therefore spread conditionally.
 * - Timestamps become epoch seconds, because that is what a JWT claim is.
 * - `null` becomes `null`, not absent, where the domain type says
 *   `T | null` - `EvaluationUser.fhirUser` is required and nullable, and quietly
 *   dropping it would make a template render `undefined` instead of failing.
 *
 * Author: John Grimes
 */

import type { Client } from "../schema/clients.js";
import type { Endpoint, EndUser } from "../schema/endpoints.js";
import type { AccessToken } from "../schema/runtime.js";
import type {
  EndpointCapabilityConfig,
  EvaluationClient,
  EvaluationEndpoint,
  EvaluationUser,
  IntrospectableToken,
  LaunchContext,
} from "@signet/core";

/**
 * Converts a timestamp to the epoch seconds a JWT claim carries.
 *
 * Truncated rather than rounded: rounding up would produce an `exp` one second
 * later than the row says the token expires, and a resource server that trusts
 * the claim would then accept a token Signet considers dead.
 */
export function epochSeconds(at: Date): number {
  return Math.floor(at.getTime() / 1000);
}

/**
 * Shapes an access token row for introspection and revocation.
 *
 * `active` is not decided here. The row carries `revokedAt` and `expiresAt`
 * through unchanged so that `@signet/core`'s introspection shaping makes that
 * judgement in one place, against one clock.
 *
 * @param row - The stored metadata for an issued token.
 * @param clientId - The OAuth `client_id`, joined from `clients`; the row itself
 *   holds only the surrogate key.
 */
export function toIntrospectableToken(
  row: AccessToken,
  clientId: string,
): IntrospectableToken {
  return {
    jti: row.jti,
    clientId,
    subject: row.subject,
    scope: row.scope,
    issuer: row.issuer,
    audience: row.audience,
    issuedAt: epochSeconds(row.issuedAt),
    expiresAt: epochSeconds(row.expiresAt),
    revokedAt: row.revokedAt === null ? null : epochSeconds(row.revokedAt),
    launchContext: row.launchContext,
    idTokenClaims: row.idTokenClaims,
  };
}

/**
 * Shapes an endpoint for policy evaluation.
 *
 * The issuer is passed in rather than derived: it is a function of the
 * deployment's public URL, which is configuration the database does not hold.
 */
export function toEvaluationEndpoint(
  endpoint: Endpoint,
  tenantSlug: string,
  issuer: string,
): EvaluationEndpoint {
  return {
    tenantSlug,
    slug: endpoint.slug,
    issuer,
    fhirBaseUrl: endpoint.fhirBaseUrl,
  };
}

/** Shapes a client for policy evaluation. */
export function toEvaluationClient(client: Client): EvaluationClient {
  return {
    clientId: client.clientId,
    name: client.name,
    type: client.clientType,
    attributes: client.attributes,
  };
}

/**
 * Shapes an end user for policy evaluation.
 *
 * No credential material crosses this boundary. `EvaluationUser` has no field
 * for a password hash, which is what stops a policy template from being able to
 * emit one into a token.
 */
export function toEvaluationUser(user: EndUser): EvaluationUser {
  return {
    id: user.id,
    fhirUser: user.fhirUserReference,
    displayName: user.displayName,
    roles: user.roles,
    attributes: user.attributes,
  };
}

/**
 * Shapes an endpoint for discovery-document generation.
 *
 * Every capability flag is copied explicitly. A spread would compile after a new
 * flag was added to the schema but not to `EndpointCapabilityConfig`, and the
 * endpoint would then advertise a capability the discovery builder knows nothing
 * about - so the tedium here is the point.
 */
export function toCapabilityConfig(
  endpoint: Endpoint,
  issuer: string,
): EndpointCapabilityConfig {
  return {
    issuer,
    fhirBaseUrl: endpoint.fhirBaseUrl,

    supportsEhrLaunch: endpoint.supportsEhrLaunch,
    supportsStandaloneLaunch: endpoint.supportsStandaloneLaunch,
    supportsAuthorizePost: endpoint.supportsAuthorizePost,

    allowsPublicClients: endpoint.allowsPublicClients,
    allowsConfidentialSymmetricClients:
      endpoint.allowsConfidentialSymmetricClients,
    allowsConfidentialAsymmetricClients:
      endpoint.allowsConfidentialAsymmetricClients,

    supportsOpenIdConnect: endpoint.supportsOpenIdConnect,

    supportsPatientBanner: endpoint.supportsPatientBanner,
    supportsStyling: endpoint.supportsStyling,

    supportsEhrPatientContext: endpoint.supportsEhrPatientContext,
    supportsEhrEncounterContext: endpoint.supportsEhrEncounterContext,
    supportsStandalonePatientContext: endpoint.supportsStandalonePatientContext,
    supportsStandaloneEncounterContext:
      endpoint.supportsStandaloneEncounterContext,

    supportsOfflineAccess: endpoint.supportsOfflineAccess,
    supportsOnlineAccess: endpoint.supportsOnlineAccess,
    supportsPatientScopes: endpoint.supportsPatientScopes,
    supportsUserScopes: endpoint.supportsUserScopes,
    supportsV1Scopes: endpoint.supportsV1Scopes,
    supportsV2Scopes: endpoint.supportsV2Scopes,

    supportsBackendServices: endpoint.supportsBackendServices,
    supportsDynamicRegistration: endpoint.supportsDynamicRegistration,

    scopesSupported: endpoint.scopesSupported,

    // Absent rather than null: an endpoint with no brand bundle must not publish
    // `"user_access_brand_bundle": null` in its discovery document.
    ...(endpoint.userAccessBrandBundle === null
      ? {}
      : { userAccessBrandBundle: endpoint.userAccessBrandBundle }),
    ...(endpoint.userAccessBrandIdentifier === null
      ? {}
      : { userAccessBrandIdentifier: endpoint.userAccessBrandIdentifier }),
  };
}

/**
 * A persona's pre-set launch context, or an empty context when it has none.
 *
 * Returning `{}` rather than null keeps the caller from having to decide what
 * "no default context" means every time it resolves one.
 */
export function toDefaultLaunchContext(user: EndUser): LaunchContext {
  return user.defaultContext ?? {};
}
