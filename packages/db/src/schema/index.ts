/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The complete Signet database schema.
 *
 * Drizzle needs one module exporting every table so that `drizzle-kit` can
 * diff the whole schema and so that a `Database` handle can be typed against
 * it. Import from here rather than from the individual concern modules.
 *
 * Author: John Grimes
 */

export * from "./audit.js";
export * from "./clients.js";
export * from "./endpoints.js";
export * from "./enums.js";
export * from "./policies.js";
export * from "./runtime.js";
export * from "./tenancy.js";
export * from "./trust.js";
