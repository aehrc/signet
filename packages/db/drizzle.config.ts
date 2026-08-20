/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * drizzle-kit configuration.
 *
 * `generate` diffs the schema modules against the recorded snapshot and needs no
 * database; the credentials below exist only for `migrate` and `studio`, and
 * fall back to a local development URL so that neither command silently targets
 * the wrong server when the variable is unset.
 *
 * Author: John Grimes
 */

import { defineConfig } from "drizzle-kit";

export default defineConfig({
  dialect: "postgresql",
  schema: "./src/schema/index.ts",
  out: "./drizzle",
  dbCredentials: {
    url:
      process.env["SIGNET_DATABASE_URL"] ??
      "postgres://signet:signet@localhost:5432/signet",
  },
  // Refuse to apply a destructive statement without an explicit confirmation:
  // a dropped column in this schema is a dropped credential or audit record.
  strict: true,
  verbose: true,
});
