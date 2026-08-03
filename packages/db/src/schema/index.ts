/**
 * The complete Signet database schema.
 *
 * Drizzle needs one module exporting every table so that `drizzle-kit` can
 * diff the whole schema and so that a `Database` handle can be typed against
 * it. Import from here rather than from the individual concern modules.
 */

export * from "./audit.js";
export * from "./clients.js";
export * from "./endpoints.js";
export * from "./enums.js";
export * from "./policies.js";
export * from "./runtime.js";
export * from "./tenancy.js";
