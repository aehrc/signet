/**
 * Tenant-scoped data access.
 *
 * Import from here rather than from the individual modules. The one thing worth
 * knowing before reading any of them: no function that touches tenant-owned data
 * takes a tenant identifier, and none takes a connection either. They take a
 * `BoundTenantScope`, `BoundEndpointScope` or `BoundClientScope` - branded values
 * that cannot be constructed outside `./scope.ts`, each carrying both the proof that
 * a tenant was resolved and the transaction that declared it to the database. So a
 * caller has to prove which tenant it is in before it can ask a question, "forgot to
 * filter by tenant" is not an expressible mistake, and neither is "filtered for a
 * tenant other than the one declared": there is no expression naming both.
 *
 * Scopes are obtained in exactly four places, and every one of them checks
 * something:
 *
 * - `resolveIssuer` / `resolveTenantScope`, from a URL, for the OAuth endpoints.
 * - `resolveTenantScopeForMember`, which requires a `tenant_members` row - the
 *   console's authorisation check.
 * - `findLiveApiToken`, which requires an unrevoked, unexpired token naming the
 *   tenant.
 * - `endpointScopeFromRow` / `clientScopeFromRow`, which narrow an existing scope
 *   and throw if the row does not belong to it.
 *
 * A binding does not outlive the transaction that made it. A scope resolved in one
 * transaction and used in the next is the ordinary shape of the OAuth code and is
 * correct - the proof survives, the declaration does not - so `withTenantScope`
 * declares again rather than reusing a transaction that has committed.
 *
 * Author: John Grimes
 */

export * from "./accessTokens.js";
export * from "./adminPasskeys.js";
export * from "./adminUsers.js";
export * from "./apiTokens.js";
export * from "./authorizationCodes.js";
export * from "./authorizationSessions.js";
export * from "./clientRequests.js";
export * from "./clients.js";
export * from "./consents.js";
export * from "./endpointKeys.js";
export * from "./endpoints.js";
export * from "./endUsers.js";
export * from "./endUserSessions.js";
export * from "./federationStates.js";
export * from "./errors.js";
export * from "./executor.js";
export * from "./jtiReplay.js";
export * from "./launchContexts.js";
export * from "./mappers.js";
export * from "./members.js";
export * from "./policies.js";
export * from "./predicates.js";
export * from "./refreshTokens.js";
export * from "./roles.js";
export * from "./routines.js";
export * from "./rows.js";
export * from "./scope.js";
export * from "./sweep.js";
export * from "./tenants.js";
export * from "./time.js";
