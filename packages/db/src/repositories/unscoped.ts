/**
 * What this package may still do without a tenant.
 *
 * Every function that reads or writes tenant-owned data takes a
 * {@link BoundTenantScope}: the tenant it acts for has been declared to the
 * database, and the transaction carrying that declaration is the same value. A
 * function that instead takes a bare {@link Executor} is a function that can reach
 * the database with no tenant declared, and there are a few that legitimately
 * must - the ones that establish which tenant the work is for, and the
 * maintenance path that is cross-tenant by design.
 *
 * That set is the escape hatch, and an escape hatch nobody enumerates is not much
 * better than no guarantee at all. So it is declared here with a justification
 * each, and `./unscoped.test.ts` compares the declaration against the source: a
 * new function taking an unbound executor fails a test rather than passing
 * unnoticed. It is the same pattern `RLS_EXEMPT_TABLES` in `../rls.ts` uses, for
 * the same reason.
 *
 * The declaration is by name rather than by type, because the property is about
 * what a reviewer can enumerate. A type could express "takes an executor", and the
 * compiler already does; what it cannot express is "and somebody thought about
 * whether that is acceptable".
 *
 * Author: John Grimes
 */

/**
 * Modules whose every function reaches only tables the policies exempt.
 *
 * Declared per module rather than per function because the justification is a
 * property of the tables, not of the individual reads: repeating it fourteen times
 * would make it look like fourteen decisions.
 */
export const UNSCOPED_MODULES: Readonly<Record<string, string>> = {
  "repositories/adminUsers":
    "Reaches only admin_users and admin_sessions, both exempt in RLS_EXEMPT_TABLES: a person is not a tenant's property, and the console session is what determines which tenants the caller may see, so it is resolved before any tenant is known.",
};

/**
 * Individual functions permitted to reach the database without a tenant.
 *
 * Keyed by the module's path within `packages/db/src`, without its extension,
 * followed by the function's name.
 */
export const UNSCOPED_FUNCTIONS: Readonly<Record<string, string>> = {
  "repositories/routines.tenantIdForSlug":
    "The tenant slug in /t/{slug} is the only tenant identifier an incoming OAuth or console request carries, so turning it into a tenant necessarily precedes declaring one. Reaches one security definer routine that returns a uuid or NULL, and no table.",
  "repositories/routines.tenantIdForApiTokenDigest":
    "A personal access token is presented with no tenant in the request, and api_tokens is tenant-owned, so the row cannot be found under the policies. Reaches one security definer routine, takes the digest rather than the token, and returns a uuid or NULL.",
  "repositories/routines.tenantIdsForAdminUser":
    "Answering which tenants a signed-in console user may see necessarily precedes choosing one, and is the only genuinely cross-tenant read the server performs. Reaches one security definer routine that returns tenant ids and nothing else.",
  "repositories/scope.declareTenantScope":
    "The function that makes a transaction's tenant known to the database. It necessarily receives the transaction before anything has been declared on it, since declaring is what it does.",
  "repositories/scope.withDeclaredTenant":
    "The resolvers' primitive: it declares a tenant identified by uuid alone, because the scope that would prove the tenant was resolved is built from the rows this read returns and so cannot exist yet. Called only by the resolvers, each of which has just been handed that uuid by a routine above or by an already-authenticated console session.",
  "repositories/scope.resolveTenantScope":
    "Turns the /t/{slug} segment into a scope, which is what establishes the tenant every later query binds to. Reads the tenant row inside a transaction declared for the identifier the slug routine returned, so the only thing it reaches unbound is that routine.",
  "repositories/scope.resolveIssuer":
    "Turns /t/{tenant}/e/{endpoint} into a scope, which every OAuth request begins with and therefore precedes any tenant being known. Reads both rows inside a transaction declared for the identifier the slug routine returned; the endpoint row, which holds a tenant's configuration, is deliberately read after binding rather than returned by a routine.",
  "repositories/members.resolveTenantScopeForMember":
    "The console's authorisation check, and the only way a browser request obtains a tenant scope, so it necessarily precedes having one. Reaches the slug routine for the identifier and then runs the membership join inside a transaction declared for it - the declaration makes the tenant reachable, the join makes it the caller's.",
  "repositories/apiTokens.findLiveApiToken":
    "A personal access token names its tenant and is presented with no tenant in the request, so resolving it is what establishes one. Reaches the digest routine for the identifier and then evaluates the revocation and expiry predicates inside a transaction declared for it, so the conditions that decide whether the token may be used stay in one query.",
  "repositories/tenants.createTenant":
    "The one write that brings a tenant into existence, so there is no established tenant for it to take. It generates the identifier itself and declares that before inserting, so the row it writes is one the policy on tenants permits - the insert is bound like every other, just to a tenant it chose rather than one it resolved.",
  "repositories/tenants.listTenantsForAdminUser":
    "The console's tenant switcher, which answers which tenants a signed-in operator may see and therefore precedes choosing one. Reaches the admin routine for the identifiers and then reads each tenant's row inside a transaction declared for that tenant, so no query it issues sees more than one tenant.",
  "repositories/scope.databaseNow":
    "Reads the transaction clock and no table at all, so there is no tenant for it to be scoped to. Exists so that a caller needing the instant a conditional update compared against gets it from the same source rather than from the process clock.",
  "repositories/sweep.sweepExpiredRuntimeRows":
    "Deletes expired runtime rows across every tenant, which is what a maintenance job is for, and is therefore reachable only with the owning identity. Attempted with the serving role it affects no rows, so its existence grants the server no cross-tenant capability.",
};

/**
 * The expiry sweep's per-table deletes.
 *
 * Declared as a set with one justification rather than nine identical ones,
 * because they are one decision: the sweep is cross-tenant by design, and these
 * are the statements it is made of. `./sweep.ts` is their only caller.
 *
 * Every predicate is a property of the row itself - an expiry that has passed -
 * so none of them can match a row that is still usable, and none returns anything
 * but a count. That, together with requiring the owning identity, is what makes a
 * job with no tenant acceptable: attempted with the serving role each of these
 * deletes nothing, because the policies hide every row from a connection that has
 * declared no tenant.
 */
export const SWEEP_FUNCTIONS: readonly string[] = [
  "repositories/accessTokens.deleteExpiredAccessTokens",
  "repositories/adminUsers.deleteExpiredAdminSessions",
  "repositories/authorizationCodes.deleteExpiredAuthorizationCodes",
  "repositories/authorizationSessions.deleteExpiredAuthorizationSessions",
  "repositories/consents.deleteExpiredConsents",
  "repositories/endUserSessions.deleteExpiredEndUserSessions",
  "repositories/jtiReplay.deleteExpiredJtis",
  "repositories/launchContexts.deleteExpiredLaunchContexts",
  "repositories/refreshTokens.deleteExpiredRefreshTokens",
];

/**
 * Modules whose functions still take an unbound executor pending conversion.
 *
 * Temporary, and empty by the end of the conversion: until then the assertion
 * above would fail for every unconverted function, which would either block the
 * conversion from landing in reviewable steps or force a hundred declarations that
 * are immediately deleted. Listing the modules instead keeps the assertion biting
 * for everything already converted, and `./unscoped.test.ts` requires each entry
 * to still have an undeclared unbound function - so a module cannot stay listed
 * once it has been converted.
 */
export const MODULES_AWAITING_BINDING: readonly string[] = [
  "audit/record",
  "repositories/accessTokens",
  "repositories/authorizationCodes",
  "repositories/authorizationSessions",
  "repositories/consents",
  "repositories/federationStates",
  "repositories/jtiReplay",
  "repositories/refreshTokens",
];
