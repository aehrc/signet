/**
 * The append-only audit log.
 *
 * Nothing in the application updates or deletes an audit event; the repository
 * layer exposes insert and read only. Rows disappear in exactly one situation -
 * the tenant they belong to is deleted, which is a full erasure.
 *
 * Author: John Grimes
 */

import {
  index,
  jsonb,
  pgTable,
  text,
  timestamp,
  uuid,
} from "drizzle-orm/pg-core";

import { endpoints } from "./endpoints.js";
import { auditActorTypeEnum } from "./enums.js";
import { tenants } from "./tenancy.js";

/** One recorded action, attributable to a principal. */
export const auditEvents = pgTable(
  "audit_events",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    /**
     * Nulled when the endpoint is deleted, never cascaded: deleting one endpoint
     * must not erase the tenant's record of what happened on it. The endpoint's
     * identifier and slug are copied into `detail` at write time.
     */
    endpointId: uuid("endpoint_id").references(() => endpoints.id, {
      onDelete: "set null",
    }),
    actorType: auditActorTypeEnum("actor_type").notNull(),
    /**
     * The actor's identifier as text, and deliberately not a foreign key. Actors
     * are polymorphic - admin user, API token, end user, client or the system
     * itself - and an audit trail that a `DELETE FROM admin_users` could
     * orphan or truncate would be no audit trail at all. The identifier is also
     * echoed into `detail` alongside the actor's display name at write time, so
     * the row stays readable once the referent is gone.
     */
    actorId: text("actor_id"),
    /** Dotted verb, e.g. `client.approved` or `token.issued`. */
    action: text("action").notNull(),
    targetType: text("target_type"),
    targetId: text("target_id"),
    /** Everything specific to this action. Must contain no bearer credential. */
    detail: jsonb("detail")
      .$type<Record<string, unknown>>()
      .notNull()
      .default({}),
    ip: text("ip"),
    userAgent: text("user_agent"),
    at: timestamp("at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    // The audit browser's default view: one tenant, newest first.
    index("audit_events_tenant_id_at_idx").on(table.tenantId, table.at.desc()),
    index("audit_events_endpoint_id_at_idx").on(
      table.endpointId,
      table.at.desc(),
    ),
    index("audit_events_action_idx").on(table.action),
    index("audit_events_target_idx").on(table.targetType, table.targetId),
    index("audit_events_actor_idx").on(table.actorType, table.actorId),
  ],
);

/** An audit event row as selected. */
export type AuditEvent = typeof auditEvents.$inferSelect;
/** Values required to insert an audit event. */
export type NewAuditEvent = typeof auditEvents.$inferInsert;
