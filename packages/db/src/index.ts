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
export * from "./rls.js";
export {
  isTestSchemaReady,
  markTestSchemaReady,
  TEST_SCHEMA_READY_VARIABLE,
} from "./test/schemaReady.js";
