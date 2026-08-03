/**
 * Tenancy and administrative identity.
 *
 * A tenant owns endpoints; an admin user is a person, and may be a member of
 * several tenants. Every credential in this file is stored as a hash — Signet
 * holds no bearer secret it could hand back.
 */

import { sql } from "drizzle-orm";
import {
  index,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

import { createdAt, sessionLifecycle, timestamps } from "./columns.js";
import { tenantMemberRoleEnum } from "./enums.js";

/** An isolation boundary owning endpoints, clients, policies and audit. */
export const tenants = pgTable(
  "tenants",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    /** URL path segment, as in `/t/{slug}/e/{endpoint}`. */
    slug: text("slug").notNull(),
    name: text("name").notNull(),
    ...timestamps(),
  },
  (table) => [uniqueIndex("tenants_slug_unique").on(table.slug)],
);

/** A person who signs in to the Signet console. */
export const adminUsers = pgTable(
  "admin_users",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    email: text("email").notNull(),
    /** Argon2id PHC string. Never a recoverable password. */
    passwordHash: text("password_hash").notNull(),
    /**
     * TOTP shared secret, AES-256-GCM envelope-encrypted under
     * `SIGNET_MASTER_KEY`. Null until the user enrols a second factor.
     */
    totpSecretEncrypted: text("totp_secret_encrypted"),
    displayName: text("display_name").notNull(),
    ...createdAt(),
    lastLoginAt: timestamp("last_login_at", { withTimezone: true }),
    /** Set to lock the account out without destroying its audit trail. */
    disabledAt: timestamp("disabled_at", { withTimezone: true }),
  },
  (table) => [
    // Case-insensitive uniqueness without depending on the citext extension,
    // which a managed Postgres may not permit us to create.
    uniqueIndex("admin_users_email_unique").on(sql`lower(${table.email})`),
  ],
);

/** Grants an admin user a role within a tenant. */
export const tenantMembers = pgTable(
  "tenant_members",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    adminUserId: uuid("admin_user_id")
      .notNull()
      .references(() => adminUsers.id, { onDelete: "cascade" }),
    role: tenantMemberRoleEnum("role").notNull(),
    ...createdAt(),
  },
  (table) => [
    primaryKey({
      name: "tenant_members_pk",
      columns: [table.tenantId, table.adminUserId],
    }),
    // The primary key already indexes tenant_id; this covers the reverse
    // lookup, "which tenants may this user see?", on every console request.
    index("tenant_members_admin_user_id_idx").on(table.adminUserId),
  ],
);

/** A personal access token for scripting against the admin API. */
export const apiTokens = pgTable(
  "api_tokens",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    /**
     * SHA-256 of the presented token. Bearer credentials are stored hashed, so
     * a database disclosure cannot be replayed against the API.
     */
    tokenHash: text("token_hash").notNull(),
    role: tenantMemberRoleEnum("role").notNull(),
    /**
     * Nulled when the issuing admin user is deleted; the identifier survives in
     * the corresponding audit event so attribution is not lost.
     */
    createdBy: uuid("created_by").references(() => adminUsers.id, {
      onDelete: "set null",
    }),
    ...createdAt(),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (table) => [
    uniqueIndex("api_tokens_token_hash_unique").on(table.tokenHash),
    index("api_tokens_tenant_id_idx").on(table.tenantId),
    index("api_tokens_created_by_idx").on(table.createdBy),
    index("api_tokens_expires_at_idx").on(table.expiresAt),
  ],
);

/** A browser session for the console, keyed by an httpOnly cookie. */
export const adminSessions = pgTable(
  "admin_sessions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    adminUserId: uuid("admin_user_id")
      .notNull()
      .references(() => adminUsers.id, { onDelete: "cascade" }),
    ...sessionLifecycle(),
  },
  (table) => [
    uniqueIndex("admin_sessions_token_hash_unique").on(table.tokenHash),
    index("admin_sessions_admin_user_id_idx").on(table.adminUserId),
    index("admin_sessions_expires_at_idx").on(table.expiresAt),
  ],
);

/** A tenant row as selected. */
export type Tenant = typeof tenants.$inferSelect;
/** Values required to insert a tenant. */
export type NewTenant = typeof tenants.$inferInsert;

/** An admin user row as selected. */
export type AdminUser = typeof adminUsers.$inferSelect;
/** Values required to insert an admin user. */
export type NewAdminUser = typeof adminUsers.$inferInsert;

/** A tenant membership row as selected. */
export type TenantMember = typeof tenantMembers.$inferSelect;
/** Values required to insert a tenant membership. */
export type NewTenantMember = typeof tenantMembers.$inferInsert;

/** An API token row as selected. */
export type ApiToken = typeof apiTokens.$inferSelect;
/** Values required to insert an API token. */
export type NewApiToken = typeof apiTokens.$inferInsert;

/** An admin session row as selected. */
export type AdminSession = typeof adminSessions.$inferSelect;
/** Values required to insert an admin session. */
export type NewAdminSession = typeof adminSessions.$inferInsert;
