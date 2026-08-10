/**
 * Tenancy and administrative identity.
 *
 * A tenant owns endpoints; an admin user is a person, and may be a member of
 * several tenants. Every credential in this file is stored as a hash - Signet
 * holds no bearer secret it could hand back.
 *
 * Author: John Grimes
 */

import { sql } from "drizzle-orm";
import {
  bigint,
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

/**
 * A WebAuthn passkey registered against a console identity.
 *
 * Belongs to the person, like the identity itself: one human may administer several
 * tenants and carries one set of authenticators across all of them. An account holds
 * up to ten, and none of the columns here is a secret - see
 * {@link adminPasskeys.publicKey}.
 */
export const adminPasskeys = pgTable(
  "admin_passkeys",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    adminUserId: uuid("admin_user_id")
      .notNull()
      .references(() => adminUsers.id, { onDelete: "cascade" }),
    /**
     * The credential's WebAuthn identifier, base64url as the browser reports it.
     *
     * Unique across the whole table rather than per account: a credential belongs
     * to exactly one identity, and sign-in resolves the identity *from* it, so two
     * accounts claiming one credential would make that resolution ambiguous.
     */
    credentialId: text("credential_id").notNull(),
    /**
     * The COSE public key, base64url.
     *
     * Stored in the clear, deliberately, and the first stored credential material
     * in Signet that is neither hashed nor encrypted. The hash-or-encrypt rule is
     * about secrets: holding a public key grants nothing, the private half never
     * leaves the authenticator, hashing would make verification impossible, and
     * encrypting would spend the master key on material that is not secret. Text
     * rather than `bytea` for the reason `endpoint_keys.private_jwk_encrypted` is:
     * a logical dump stays human-transportable.
     */
    publicKey: text("public_key").notNull(),
    /**
     * The last signature counter accepted from this authenticator.
     *
     * Stays zero for the authenticators that do not count, which is most platform
     * ones. See `counterAccepted` in `@signet/core` for what a non-zero value then
     * obliges.
     */
    counter: bigint("counter", { mode: "number" }).notNull().default(0),
    /** Transport hints from registration, echoed back to the browser at sign-in. */
    transports: text("transports").array().notNull().default([]),
    /** User-supplied or defaulted label. The only thing that tells two apart. */
    name: text("name").notNull(),
    ...createdAt(),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
  },
  (table) => [
    uniqueIndex("admin_passkeys_credential_id_unique").on(table.credentialId),
    index("admin_passkeys_admin_user_id_idx").on(table.adminUserId),
  ],
);

/**
 * An outstanding WebAuthn ceremony challenge.
 *
 * A row rather than a signed value or a process-local map, because the requirement
 * is single use and only a row that is deleted on consumption gives that across
 * restarts and replicas. Consumption is one `DELETE … RETURNING`, so two callers
 * presenting the same challenge cannot both win it.
 */
export const adminPasskeyChallenges = pgTable(
  "admin_passkey_challenges",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    /** The random value the ceremony signs over, base64url. */
    challenge: text("challenge").notNull(),
    /** `registration` or `authentication`; a challenge is not valid for both. */
    purpose: text("purpose").notNull(),
    /**
     * The identity a registration challenge was minted for.
     *
     * Null for an authentication challenge, which is issued before anybody has
     * identified themselves - that is the point of a discoverable credential. A
     * registration challenge is bound to the account whose password minted it, and
     * the verify step compares the two.
     */
    adminUserId: uuid("admin_user_id").references(() => adminUsers.id, {
      onDelete: "cascade",
    }),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    ...createdAt(),
  },
  (table) => [
    uniqueIndex("admin_passkey_challenges_challenge_unique").on(
      table.challenge,
    ),
    index("admin_passkey_challenges_admin_user_id_idx").on(table.adminUserId),
    index("admin_passkey_challenges_expires_at_idx").on(table.expiresAt),
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

/** A registered passkey as selected. */
export type AdminPasskey = typeof adminPasskeys.$inferSelect;
/** Values required to insert a passkey. */
export type NewAdminPasskey = typeof adminPasskeys.$inferInsert;

/** An outstanding ceremony challenge as selected. */
export type AdminPasskeyChallenge = typeof adminPasskeyChallenges.$inferSelect;
/** Values required to insert a ceremony challenge. */
export type NewAdminPasskeyChallenge =
  typeof adminPasskeyChallenges.$inferInsert;
