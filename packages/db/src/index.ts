/**
 * Author: John Grimes
 */

export {
  createDatabase,
  pingDatabase,
  type Database,
  type DatabaseHandle,
  type DatabaseOptions,
} from "./client.js";

export * from "./schema/index.js";
export * from "./repositories/index.js";
export * from "./crypto/index.js";
export * from "./audit/index.js";
export * from "./migrations.js";
export * from "./privileges.js";
export * from "./rls.js";
export {
  isTestSchemaReady,
  markTestSchemaReady,
  TEST_SCHEMA_READY_VARIABLE,
} from "./test/schemaReady.js";

// The role every suite connects as, and how its connection is derived. Exported
// because `apps/server`'s harness needs both and cannot reach into this package's
// source: only this package depends on Drizzle. See `./test/servingRole.ts`.
export {
  prepareServingRole,
  servingRoleUrl,
  SERVING_TEST_ROLE,
} from "./test/servingRole.js";

// Privilege observation, exported for the same reason `schemaReady` is: a suite
// in `apps/server` needs it and cannot write raw SQL, because only this package
// depends on Drizzle. See `./test/privilegeProbe.ts`.
export {
  createProbeRole,
  dropProbeRole,
  listSignetRoutines,
  roleCanExecute,
  roleHasDefaultTablePrivileges,
  roleHasTablePrivilege,
  type TablePrivilege,
} from "./test/privilegeProbe.js";
