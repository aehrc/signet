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
  "repositories/scope.declareTenantScope":
    "The function that makes a transaction's tenant known to the database. It necessarily receives the transaction before anything has been declared on it, since declaring is what it does.",
  "repositories/scope.databaseNow":
    "Reads the transaction clock and no table at all, so there is no tenant for it to be scoped to. Exists so that a caller needing the instant a conditional update compared against gets it from the same source rather than from the process clock.",
  "repositories/sweep.sweepExpiredRuntimeRows":
    "Deletes expired runtime rows across every tenant, which is what a maintenance job is for, and is therefore reachable only with the owning identity. Attempted with the serving role it affects no rows, so its existence grants the server no cross-tenant capability.",
};

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
  "repositories/apiTokens",
  "repositories/authorizationCodes",
  "repositories/authorizationSessions",
  "repositories/clientRequests",
  "repositories/clients",
  "repositories/consents",
  "repositories/endUserSessions",
  "repositories/endUsers",
  "repositories/endpointKeys",
  "repositories/endpoints",
  "repositories/federationStates",
  "repositories/jtiReplay",
  "repositories/launchContexts",
  "repositories/members",
  "repositories/policies",
  "repositories/refreshTokens",
  "repositories/scope",
  "repositories/tenants",
];
