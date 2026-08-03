/**
 * Registered SMART apps and the self-serve registration queue.
 *
 * `clients.client_id` is globally unique rather than unique per endpoint. A
 * client identifier travels in tokens, introspection responses and app
 * configuration, where no endpoint is in scope to disambiguate it; making it
 * globally unique means it can be referenced directly from the runtime tables.
 */

import {
  index,
  jsonb,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

import { createdAt, timestamps } from "./columns.js";
import { endpoints } from "./endpoints.js";
import {
  clientRequestStatusEnum,
  clientStatusEnum,
  clientTypeEnum,
  grantTypeEnum,
} from "./enums.js";
import { adminUsers } from "./tenancy.js";

import type { ClientType } from "@signet/core";

/**
 * What a developer submits when asking for a client on an endpoint.
 *
 * Stored as a single JSONB document rather than shredded into columns: it is an
 * unapproved proposal, not configuration, and it must be retained verbatim for
 * the audit record of what was actually asked for.
 */
export interface ClientRequestPayload {
  readonly name: string;
  readonly description?: string;
  readonly logoUrl?: string;
  readonly clientType: ClientType;
  readonly redirectUris: readonly string[];
  readonly launchUri?: string;
  readonly requestedScopes: readonly string[];
  readonly contactEmail: string;
  /** Free-text justification shown to the reviewing admin. */
  readonly note?: string;
}

/** A SMART app registered against an endpoint. */
export const clients = pgTable(
  "clients",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    endpointId: uuid("endpoint_id")
      .notNull()
      .references(() => endpoints.id, { onDelete: "cascade" }),
    /** The OAuth `client_id`. Globally unique; see the file header. */
    clientId: text("client_id").notNull(),
    name: text("name").notNull(),
    description: text("description"),
    logoUrl: text("logo_url"),
    clientType: clientTypeEnum("client_type").notNull(),
    /**
     * Argon2id PHC string for a confidential-symmetric client's secret. Null for
     * public and asymmetric clients. Never a recoverable secret: a lost secret
     * is rotated, not recovered.
     */
    secretHash: text("secret_hash"),
    secretExpiresAt: timestamp("secret_expires_at", { withTimezone: true }),
    /** Inline JWKS for `private_key_jwt`. Mutually exclusive with `jwksUri`. */
    jwks: jsonb("jwks").$type<Record<string, unknown>>(),
    /**
     * Remote JWKS location. User-supplied, so every fetch goes through the SSRF
     * guard that blocks private and link-local ranges.
     */
    jwksUri: text("jwks_uri"),
    jwksCachedAt: timestamp("jwks_cached_at", { withTimezone: true }),
    /** Compared by exact match at `/authorize`, never by prefix. */
    redirectUris: text("redirect_uris").array().notNull().default([]),
    /** Where an EHR launch sends the browser, with `iss` and `launch`. */
    launchUri: text("launch_uri"),
    grantTypes: grantTypeEnum("grant_types").array().notNull(),
    /** Ceiling on what this client may request; the policy narrows further. */
    allowedScopes: text("allowed_scopes").array().notNull().default([]),
    status: clientStatusEnum("status").notNull().default("pending"),
    contactEmail: text("contact_email"),
    /** Attributes a policy may template from, e.g. a vendor tag. */
    attributes: jsonb("attributes")
      .$type<Record<string, unknown>>()
      .notNull()
      .default({}),
    /** Nulled when the approving admin is deleted; audit retains the identifier. */
    createdBy: uuid("created_by").references(() => adminUsers.id, {
      onDelete: "set null",
    }),
    ...timestamps(),
  },
  (table) => [
    uniqueIndex("clients_client_id_unique").on(table.clientId),
    index("clients_endpoint_id_idx").on(table.endpointId),
    index("clients_created_by_idx").on(table.createdBy),
  ],
);

/** A developer's request for a client, awaiting review. */
export const clientRequests = pgTable(
  "client_requests",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    endpointId: uuid("endpoint_id")
      .notNull()
      .references(() => endpoints.id, { onDelete: "cascade" }),
    requestedByEmail: text("requested_by_email").notNull(),
    payload: jsonb("payload").$type<ClientRequestPayload>().notNull(),
    status: clientRequestStatusEnum("status").notNull().default("pending"),
    /** Nulled when the reviewing admin is deleted; the decision itself stands. */
    reviewerId: uuid("reviewer_id").references(() => adminUsers.id, {
      onDelete: "set null",
    }),
    decisionNote: text("decision_note"),
    ...createdAt(),
    decidedAt: timestamp("decided_at", { withTimezone: true }),
    /**
     * The client an approval produced. Nulled if that client is later deleted,
     * so the request history survives the client it created.
     */
    resultingClientId: uuid("resulting_client_id").references(
      () => clients.id,
      { onDelete: "set null" },
    ),
  },
  (table) => [
    index("client_requests_endpoint_id_status_idx").on(
      table.endpointId,
      table.status,
    ),
    index("client_requests_reviewer_id_idx").on(table.reviewerId),
    index("client_requests_resulting_client_id_idx").on(
      table.resultingClientId,
    ),
  ],
);

/** A client row as selected. */
export type Client = typeof clients.$inferSelect;
/** Values required to insert a client. */
export type NewClient = typeof clients.$inferInsert;

/** A client registration request row as selected. */
export type ClientRequest = typeof clientRequests.$inferSelect;
/** Values required to insert a client registration request. */
export type NewClientRequest = typeof clientRequests.$inferInsert;
