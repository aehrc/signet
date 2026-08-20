/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { text, timestamp, uuid } from "drizzle-orm/pg-core";

import { adminUsers } from "./tenancy.js";

import type { AnyPgColumn } from "drizzle-orm/pg-core";

/** A table this module can build a foreign key to. */
type AnyPgTableWithId = { readonly id: AnyPgColumn };

/**
 * Column conventions shared across the schema.
 *
 * These are factories rather than shared builder instances: a Drizzle column
 * builder carries the name it was constructed with, so handing the same object
 * to two tables invites the sort of aliasing bug that only shows up in generated
 * DDL. Calling a factory per table keeps each column its own value.
 *
 * Naming the conventions in one place also means a table cannot quietly acquire
 * a timestamp without a time zone, which for token expiry would be a correctness
 * bug rather than a style one.
 */

/** `created_at`, stamped by the database on insert. */
export function createdAt() {
  return {
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  };
}

/** `created_at` and `updated_at`, for rows an operator edits over time. */
export function timestamps() {
  return {
    ...createdAt(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  };
}

/**
 * The lifecycle of a single-use credential: created, expires, and consumed
 * exactly once.
 *
 * `consumedAt` being nullable is what makes redemption safe - the conditional
 * `UPDATE ... WHERE consumed_at IS NULL` in the repositories relies on it, so
 * two concurrent redemptions cannot both succeed.
 */
export function singleUseLifecycle() {
  return {
    ...createdAt(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    consumedAt: timestamp("consumed_at", { withTimezone: true }),
  };
}

/**
 * The two references a row about one person on one endpoint carries.
 *
 * `consents` and `end_user_sessions` both hang off the pair, and both cascade from either
 * side: deleting an endpoint or an account takes what belonged to it, because a consent
 * or a session for a deleted account is not something anything should be able to read.
 *
 * The referenced tables are passed in rather than imported, because `./endpoints.js`
 * imports this module and a cycle between them is exactly the kind of thing that fails
 * confusingly at import time rather than at build time.
 *
 * @param endpoints - The `endpoints` table.
 * @param endUsers - The `end_users` table.
 */
export function endpointAndEndUser(
  endpoints: AnyPgTableWithId,
  endUsers: AnyPgTableWithId,
) {
  return {
    endpointId: uuid("endpoint_id")
      .notNull()
      .references(() => endpoints.id, { onDelete: "cascade" }),
    endUserId: uuid("end_user_id")
      .notNull()
      .references(() => endUsers.id, { onDelete: "cascade" }),
  };
}

/**
 * The columns a browser session row carries.
 *
 * Shared by `admin_sessions` and `end_user_sessions`, which are different credentials
 * belonging to different kinds of person and have identical shape: a digest of the
 * cookie, when it was issued, when it expires, whether it was revoked, and where it came
 * from. Writing the group out twice invited the two to drift into different expiry
 * semantics.
 *
 * `ip` is text rather than `inet` because the value derives from a proxy header and must
 * be storable even when it is not a well-formed address.
 */
export function sessionLifecycle() {
  return {
    /** SHA-256 of the cookie value. Stored hashed, never in clear. */
    tokenHash: text("token_hash").notNull(),
    ...createdAt(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    ip: text("ip"),
    userAgent: text("user_agent"),
  };
}

/**
 * A nullable reference to the admin user who created a row.
 *
 * `SET NULL` rather than cascade: deleting an operator must not erase the
 * configuration they created.
 */
export function createdByAdmin() {
  return {
    createdBy: uuid("created_by").references(() => adminUsers.id, {
      onDelete: "set null",
    }),
  };
}

/**
 * The lifecycle of an issued, revocable credential: when it was minted, when it
 * lapses, and whether it was revoked early.
 *
 * Distinct from {@link singleUseLifecycle}: an access or refresh token may be
 * presented many times until it expires, so the question is "still valid?" rather
 * than "already spent?". Introspection treats an expired token and a revoked one
 * identically, but the two columns are kept apart so the audit trail can say
 * which happened.
 */
export function revocableLifecycle() {
  return {
    issuedAt: timestamp("issued_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  };
}
