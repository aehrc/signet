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
