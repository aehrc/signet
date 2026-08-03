import { timestamp, uuid } from "drizzle-orm/pg-core";

import { adminUsers } from "./tenancy.js";

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
 * `consumedAt` being nullable is what makes redemption safe — the conditional
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
