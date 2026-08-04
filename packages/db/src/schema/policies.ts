/**
 * Versioned scope→claims policies.
 *
 * Policy versions are immutable rows: editing produces a new version so that a
 * change can be diffed and rolled back, and so an audit event can name the exact
 * document that authorised a token.
 *
 * Author: John Grimes
 */

import { sql } from "drizzle-orm";
import {
  boolean,
  index,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

import { clients } from "./clients.js";
import { createdAt } from "./columns.js";
import { endpoints } from "./endpoints.js";
import { adminUsers } from "./tenancy.js";

import type { PolicyDocument } from "@signet/core";

/** One immutable version of an endpoint's policy document. */
export const policies = pgTable(
  "policies",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    endpointId: uuid("endpoint_id")
      .notNull()
      .references(() => endpoints.id, { onDelete: "cascade" }),
    /** Monotonically increasing within the endpoint, starting at 1. */
    version: integer("version").notNull(),
    document: jsonb("document").$type<PolicyDocument>().notNull(),
    published: boolean("published").notNull().default(false),
    /** Nulled when the authoring admin is deleted; the version stands. */
    createdBy: uuid("created_by").references(() => adminUsers.id, {
      onDelete: "set null",
    }),
    ...createdAt(),
    /** The author's description of the change, shown beside the diff. */
    note: text("note"),
  },
  (table) => [
    uniqueIndex("policies_endpoint_id_version_unique").on(
      table.endpointId,
      table.version,
    ),
    // At most one published version per endpoint, enforced by the database
    // rather than by application code. Two published versions would make token
    // issuance depend on row order, which is the kind of ambiguity an
    // authorization server must not be able to reach.
    uniqueIndex("policies_one_published_per_endpoint")
      .on(table.endpointId)
      .where(sql`${table.published}`),
    index("policies_endpoint_id_idx").on(table.endpointId),
    index("policies_created_by_idx").on(table.createdBy),
  ],
);

/**
 * A per-client policy replacing the endpoint's published policy.
 *
 * The document is complete rather than a patch: merging two rule lists has no
 * unambiguous meaning - ordering is significant in both - so an override
 * substitutes wholesale and the console shows the difference.
 */
export const clientPolicyOverrides = pgTable("client_policy_overrides", {
  clientId: uuid("client_id")
    .primaryKey()
    .references(() => clients.id, { onDelete: "cascade" }),
  document: jsonb("document").$type<PolicyDocument>().notNull(),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

/** A policy version row as selected. */
export type Policy = typeof policies.$inferSelect;
/** Values required to insert a policy version. */
export type NewPolicy = typeof policies.$inferInsert;

/** A client policy override row as selected. */
export type ClientPolicyOverride = typeof clientPolicyOverrides.$inferSelect;
/** Values required to insert a client policy override. */
export type NewClientPolicyOverride = typeof clientPolicyOverrides.$inferInsert;
