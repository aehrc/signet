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
export * from "./enforcement.js";
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

// Activity observation, for the assertion that no transaction is held across an
// outbound request. See `./test/activityProbe.ts`.
export {
  createActivityProbe,
  type ActivityProbe,
} from "./test/activityProbe.js";

// Counting outstanding ceremony challenges, so the server's passkey suite can
// assert that a refused request minted none. See `./test/passkeyProbe.ts`.
export { countAdminPasskeyChallenges } from "./test/passkeyProbe.js";

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
  type ProbeRoleOptions,
  type TablePrivilege,
} from "./test/privilegeProbe.js";

// The connections and the empty database the startup check's own suite needs, for
// the same reason again: `apps/server/src/enforcement.integration.test.ts` has to
// connect as four different identities and observe one unmigrated database, and
// cannot write a `create database` of its own. See `./test/connectionUrl.ts` and
// `./test/scratchDatabase.ts`.
export {
  databaseUrlWith,
  type ConnectionUrlChanges,
} from "./test/connectionUrl.js";
export {
  createScratchDatabase,
  dropScratchDatabase,
} from "./test/scratchDatabase.js";
