/**
 * Registered SMART apps and the self-serve registration queue.
 *
 * `clients.client_id` is globally unique rather than unique per endpoint. A
 * client identifier travels in tokens, introspection responses and app
 * configuration, where no endpoint is in scope to disambiguate it; making it
 * globally unique means it can be referenced directly from the runtime tables.
 *
 * A client may additionally be *vouched*: created by an endpoint's trust anchor
 * from a software statement the anchor signed, rather than by an administrator.
 * The three `vouched*` columns record which anchor, which statement, and when the
 * vouching lapses. See `./trust.ts` for the rule that permits any of it.
 *
 * Author: John Grimes
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

    /**
     * The trust anchor whose software statement created this client.
     *
     * Null for every client an administrator or the developer portal created,
     * which is what "vouched" is defined against: the three columns below are
     * set together at registration and never edited, so a client is vouched
     * exactly when it carries all three.
     */
    vouchedByIssuer: text("vouched_by_issuer"),
    /**
     * The statement's `jti`, unique with `endpoint_id`.
     *
     * The uniqueness is the replay arbiter, not a data-quality nicety: one
     * statement vouches for one registration, and two registrations racing with
     * the same statement are resolved by the insert - exactly one wins, and the
     * loser is refused. A read-then-insert would let both find nothing.
     */
    vouchedStatementId: text("vouched_statement_id"),
    /**
     * When the vouching lapses, after which no grant type issues a token.
     *
     * Enforced at the issuance chokepoint rather than by deleting the client,
     * so enforcement never depends on a maintenance job having run.
     */
    vouchingExpiresAt: timestamp("vouching_expires_at", { withTimezone: true }),

    ...timestamps(),
  },
  (table) => [
    uniqueIndex("clients_client_id_unique").on(table.clientId),
    index("clients_endpoint_id_idx").on(table.endpointId),
    index("clients_created_by_idx").on(table.createdBy),
    uniqueIndex("clients_endpoint_id_vouched_statement_id_unique").on(
      table.endpointId,
      table.vouchedStatementId,
    ),
    index("clients_vouching_expires_at_idx").on(table.vouchingExpiresAt),
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
    /**
     * SHA-256 of the token the developer keeps to track this request.
     *
     * The portal is not an authenticated surface - a developer asking for a client has
     * no account yet - so the submission returns a bearer token once, and checking the
     * request's status or collecting its credentials requires presenting it. Nullable
     * because a request an administrator files on someone's behalf has nobody to hand
     * a token to.
     */
    trackingTokenHash: text("tracking_token_hash"),
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
