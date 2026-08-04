/**
 * Runtime state for the OAuth flows: launch handles, authorization sessions,
 * codes, tokens, consents and the `private_key_jwt` replay ledger.
 *
 * Two rules govern this file.
 *
 * Every bearer credential is stored as a SHA-256 digest, never in clear. A
 * digest is sufficient for the only operation Signet performs on these values -
 * look up the row for a credential the client just presented - and it means a
 * database disclosure yields nothing replayable.
 *
 * Clients are referenced by their surrogate `clients.id`, not by the OAuth
 * `client_id` string. Introspection joins once on a primary key to recover the
 * identifier, which is cheaper than carrying a wide text key through five
 * tables and impossible to get out of step.
 *
 * Author: John Grimes
 */

import {
  index,
  jsonb,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

import { clients } from "./clients.js";
import {
  createdAt,
  endpointAndEndUser,
  revocableLifecycle,
  sessionLifecycle,
  singleUseLifecycle,
} from "./columns.js";
import { endpoints, endUsers } from "./endpoints.js";

import type { LaunchContext } from "@signet/core";
import type { AnyPgColumn } from "drizzle-orm/pg-core";

/**
 * A single-use launch handle minted by an EHR, or by the console's launch
 * simulator, and redeemed at `/authorize`.
 */
export const launchContexts = pgTable(
  "launch_contexts",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    /**
     * SHA-256 of the opaque `launch` parameter. The handle itself is returned to
     * the caller once and never stored - it is a bearer credential.
     */
    handleHash: text("handle_hash").notNull(),
    endpointId: uuid("endpoint_id")
      .notNull()
      .references(() => endpoints.id, { onDelete: "cascade" }),
    /** When set, only this client may redeem the handle. */
    clientId: uuid("client_id").references(() => clients.id, {
      onDelete: "cascade",
    }),
    context: jsonb("context").$type<LaunchContext>().notNull(),
    /**
     * Free-text identifier of whoever minted the handle: an admin user, an API
     * token or an EHR client. Not a foreign key, because the creator is
     * polymorphic and the attribution must outlive any of those rows.
     */
    createdBy: text("created_by"),
    ...singleUseLifecycle(),
  },
  (table) => [
    uniqueIndex("launch_contexts_handle_hash_unique").on(table.handleHash),
    index("launch_contexts_endpoint_id_idx").on(table.endpointId),
    index("launch_contexts_client_id_idx").on(table.clientId),
    index("launch_contexts_expires_at_idx").on(table.expiresAt),
  ],
);

/** An in-flight `/authorize` request, spanning login, context and consent. */
export const authorizationSessions = pgTable(
  "authorization_sessions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    /* jscpd:ignore-start */
    // Repeated deliberately across the runtime tables. Factoring these two into
    // a shared helper was tried and reverted: spreading a function's return into
    // a `pgTable` column object defeats Drizzle's inference of the column types,
    // leaving them possibly-undefined in the index callbacks below. A foreign key
    // target and its cascade rule are also the part of a schema most worth
    // reading literally at the site that declares it.
    endpointId: uuid("endpoint_id")
      .notNull()
      .references(() => endpoints.id, { onDelete: "cascade" }),
    clientId: uuid("client_id")
      .notNull()
      .references(() => clients.id, { onDelete: "cascade" }),
    /* jscpd:ignore-end */
    requestedScopes: text("requested_scopes").array().notNull().default([]),
    /** Retained verbatim; the code is bound to it and must match exactly. */
    redirectUri: text("redirect_uri").notNull(),
    /** Nullable: `state` is strongly recommended but not mandatory in OAuth. */
    state: text("state"),
    codeChallenge: text("code_challenge"),
    /** Only `S256` is accepted; stored as text so a future method needs no enum. */
    codeChallengeMethod: text("code_challenge_method"),
    /** The `aud` the app asked for, validated against the FHIR base URL. */
    aud: text("aud"),
    nonce: text("nonce"),
    /**
     * Nulled if the launch context row is swept; `resolvedContext` already holds
     * what was resolved from it, so the session remains completable.
     */
    launchContextId: uuid("launch_context_id").references(
      () => launchContexts.id,
      { onDelete: "set null" },
    ),
    /**
     * Null until the end user authenticates. Cascades on deletion: an in-flight
     * authorization for a deleted user must not be completable.
     */
    endUserId: uuid("end_user_id").references(() => endUsers.id, {
      onDelete: "cascade",
    }),
    resolvedContext: jsonb("resolved_context").$type<LaunchContext>(),
    consentGrantedAt: timestamp("consent_granted_at", { withTimezone: true }),
    ...createdAt(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  },
  (table) => [
    index("authorization_sessions_endpoint_id_idx").on(table.endpointId),
    index("authorization_sessions_client_id_idx").on(table.clientId),
    index("authorization_sessions_launch_context_id_idx").on(
      table.launchContextId,
    ),
    index("authorization_sessions_end_user_id_idx").on(table.endUserId),
    index("authorization_sessions_expires_at_idx").on(table.expiresAt),
  ],
);

/** A single-use, 60-second authorization code bound to one session. */
export const authorizationCodes = pgTable(
  "authorization_codes",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    /** SHA-256 of the code. The code itself is never stored. */
    codeHash: text("code_hash").notNull(),
    sessionId: uuid("session_id")
      .notNull()
      .references(() => authorizationSessions.id, { onDelete: "cascade" }),
    ...singleUseLifecycle(),
  },
  (table) => [
    uniqueIndex("authorization_codes_code_hash_unique").on(table.codeHash),
    index("authorization_codes_session_id_idx").on(table.sessionId),
    index("authorization_codes_expires_at_idx").on(table.expiresAt),
  ],
);

/**
 * Metadata for an issued access token, keyed by its `jti`.
 *
 * The token itself is a self-contained signed JWT; this row exists so that
 * introspection and revocation are possible at all. `issuer` and `audience` are
 * stored rather than derived, because an endpoint's FHIR base URL can be edited
 * and a token must introspect as it was minted, not as the endpoint is now.
 */
export const accessTokens = pgTable(
  "access_tokens",
  {
    jti: text("jti").primaryKey(),
    /* jscpd:ignore-start */
    // Repeated deliberately across the runtime tables. Factoring these two into
    // a shared helper was tried and reverted: spreading a function's return into
    // a `pgTable` column object defeats Drizzle's inference of the column types,
    // leaving them possibly-undefined in the index callbacks below. A foreign key
    // target and its cascade rule are also the part of a schema most worth
    // reading literally at the site that declares it.
    endpointId: uuid("endpoint_id")
      .notNull()
      .references(() => endpoints.id, { onDelete: "cascade" }),
    clientId: uuid("client_id")
      .notNull()
      .references(() => clients.id, { onDelete: "cascade" }),
    /* jscpd:ignore-end */
    /** The end user's id, or the client id for a backend service. */
    subject: text("subject").notNull(),
    /** Granted scopes, space-delimited exactly as they appear in the token. */
    scope: text("scope").notNull(),
    issuer: text("issuer").notNull(),
    audience: text("audience").notNull(),
    launchContext: jsonb("launch_context")
      .$type<LaunchContext>()
      .notNull()
      .default({}),
    /** Present only when an `id_token` was issued alongside. */
    idTokenClaims: jsonb("id_token_claims").$type<Record<string, unknown>>(),
    ...revocableLifecycle(),
  },
  (table) => [
    index("access_tokens_endpoint_id_idx").on(table.endpointId),
    index("access_tokens_client_id_idx").on(table.clientId),
    index("access_tokens_subject_idx").on(table.subject),
    index("access_tokens_expires_at_idx").on(table.expiresAt),
  ],
);

/**
 * A refresh token, hashed, and its position in a rotation family.
 *
 * Rotation issues a successor and links to it via `replacedById`. Presenting a
 * token that already has a successor is reuse, and revokes every row sharing
 * `familyId` - which is why the family identifier is a plain indexed column and
 * not derived from the chain.
 */
export const refreshTokens = pgTable(
  "refresh_tokens",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    /** SHA-256 of the refresh token. The token itself is never stored. */
    tokenHash: text("token_hash").notNull(),
    /** Shared by every token descended from one authorization. */
    familyId: uuid("family_id").notNull(),
    /* jscpd:ignore-start */
    // Repeated deliberately across the runtime tables. Factoring these two into
    // a shared helper was tried and reverted: spreading a function's return into
    // a `pgTable` column object defeats Drizzle's inference of the column types,
    // leaving them possibly-undefined in the index callbacks below. A foreign key
    // target and its cascade rule are also the part of a schema most worth
    // reading literally at the site that declares it.
    endpointId: uuid("endpoint_id")
      .notNull()
      .references(() => endpoints.id, { onDelete: "cascade" }),
    clientId: uuid("client_id")
      .notNull()
      .references(() => clients.id, { onDelete: "cascade" }),
    /* jscpd:ignore-end */
    subject: text("subject").notNull(),
    /** Scopes this token may re-request; a refresh may narrow but never widen. */
    scope: text("scope").notNull(),
    launchContext: jsonb("launch_context")
      .$type<LaunchContext>()
      .notNull()
      .default({}),
    ...revocableLifecycle(),
    /** The successor issued when this token was rotated. */
    replacedById: uuid("replaced_by_id").references(
      (): AnyPgColumn => refreshTokens.id,
      { onDelete: "set null" },
    ),
  },
  (table) => [
    uniqueIndex("refresh_tokens_token_hash_unique").on(table.tokenHash),
    index("refresh_tokens_family_id_idx").on(table.familyId),
    index("refresh_tokens_endpoint_id_idx").on(table.endpointId),
    index("refresh_tokens_client_id_idx").on(table.clientId),
    index("refresh_tokens_replaced_by_id_idx").on(table.replacedById),
    index("refresh_tokens_expires_at_idx").on(table.expiresAt),
  ],
);

/** A remembered authorisation, so `remember` consent mode can skip the prompt. */
export const consents = pgTable(
  "consents",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    ...endpointAndEndUser(endpoints, endUsers),
    clientId: uuid("client_id")
      .notNull()
      .references(() => clients.id, { onDelete: "cascade" }),
    /** The scopes consented to, space-delimited. */
    scope: text("scope").notNull(),
    grantedAt: timestamp("granted_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    /** Set from the end user's management page; revocation is never a delete. */
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (table) => [
    index("consents_end_user_id_client_id_idx").on(
      table.endUserId,
      table.clientId,
    ),
    index("consents_endpoint_id_idx").on(table.endpointId),
    index("consents_client_id_idx").on(table.clientId),
    index("consents_expires_at_idx").on(table.expiresAt),
  ],
);

/**
 * An end user's browser session on one endpoint.
 *
 * Distinct from an `authorization_sessions` row, which is one app's authorization in
 * progress: this is "this person is signed in here", and it exists for the management
 * page. An end user reviewing which apps hold access to their record is not in the
 * middle of an authorization, so there is no authorization session to hang it off.
 *
 * Scoped to the endpoint, not to the tenant. The same person may have accounts on two
 * endpoints of the same tenant, and a session on one must not be a session on the other:
 * the accounts are separate rows with separate passwords.
 */
export const endUserSessions = pgTable(
  "end_user_sessions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    ...endpointAndEndUser(endpoints, endUsers),
    ...sessionLifecycle(),
  },
  (table) => [
    uniqueIndex("end_user_sessions_token_hash_unique").on(table.tokenHash),
    index("end_user_sessions_end_user_id_idx").on(table.endUserId),
    index("end_user_sessions_endpoint_id_idx").on(table.endpointId),
    index("end_user_sessions_expires_at_idx").on(table.expiresAt),
  ],
);

/**
 * One round trip to an upstream identity provider.
 *
 * Written when the browser is sent to the provider and consumed when it comes back.
 * The row is what makes the callback verifiable at all: `state` proves the response
 * belongs to a request Signet made, `nonce` binds the ID token to this sign-in, and
 * the PKCE verifier proves the code is being redeemed by whoever asked for it.
 *
 * `state` is hashed and the other two are not, and the asymmetry is the rule the
 * whole schema follows. `state` arrives from the browser, so it is a credential
 * presented *to* Signet and a digest is all that is needed to find the row. The
 * nonce is compared against a value inside the ID token and the verifier is sent
 * upstream, so both must be recoverable. They are short-lived, single-use, and
 * useless without the state they are stored beside.
 *
 * Single-use is enforced the same way an authorization code's is, by the
 * conditional update in the repository against `consumed_at`. A replayed callback
 * therefore finds nothing rather than signing somebody in a second time.
 */
export const federationStates = pgTable(
  "federation_states",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    endpointId: uuid("endpoint_id")
      .notNull()
      .references(() => endpoints.id, { onDelete: "cascade" }),
    /**
     * The authorization this sign-in is part of.
     *
     * Cascades: a session that expired and was swept takes its federation state
     * with it, because a callback for an authorization that no longer exists has
     * nothing to complete.
     */
    sessionId: uuid("session_id")
      .notNull()
      .references(() => authorizationSessions.id, { onDelete: "cascade" }),
    /** SHA-256 of the `state` sent upstream. The value itself is never stored. */
    stateHash: text("state_hash").notNull(),
    /** Compared against the ID token's `nonce`; must be recoverable. */
    nonce: text("nonce").notNull(),
    /** Sent to the provider's token endpoint; must be recoverable. */
    codeVerifier: text("code_verifier").notNull(),
    ...singleUseLifecycle(),
  },
  (table) => [
    uniqueIndex("federation_states_state_hash_unique").on(table.stateHash),
    index("federation_states_session_id_idx").on(table.sessionId),
    index("federation_states_endpoint_id_idx").on(table.endpointId),
    index("federation_states_expires_at_idx").on(table.expiresAt),
  ],
);

/**
 * Seen `jti` values from `private_key_jwt` client assertions.
 *
 * The composite primary key IS the replay prevention: an insert that conflicts
 * means the assertion has been presented before, and the authentication must
 * fail. It is load-bearing, not an optimisation - dropping it would silently
 * permit assertion replay within the token's validity window.
 */
export const jtiReplay = pgTable(
  "jti_replay",
  {
    clientId: uuid("client_id")
      .notNull()
      .references(() => clients.id, { onDelete: "cascade" }),
    jti: text("jti").notNull(),
    /** Sweep boundary: rows may be dropped once the assertion could not be valid. */
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "jti_replay_pk",
      columns: [table.clientId, table.jti],
    }),
    index("jti_replay_expires_at_idx").on(table.expiresAt),
  ],
);

/** A launch context row as selected. */
export type LaunchContextRow = typeof launchContexts.$inferSelect;
/** Values required to insert a launch context. */
export type NewLaunchContextRow = typeof launchContexts.$inferInsert;

/** An authorization session row as selected. */
export type AuthorizationSession = typeof authorizationSessions.$inferSelect;
/** Values required to insert an authorization session. */
export type NewAuthorizationSession = typeof authorizationSessions.$inferInsert;

/** An authorization code row as selected. */
export type AuthorizationCode = typeof authorizationCodes.$inferSelect;
/** Values required to insert an authorization code. */
export type NewAuthorizationCode = typeof authorizationCodes.$inferInsert;

/** An access token metadata row as selected. */
export type AccessToken = typeof accessTokens.$inferSelect;
/** Values required to insert access token metadata. */
export type NewAccessToken = typeof accessTokens.$inferInsert;

/** A refresh token row as selected. */
export type RefreshToken = typeof refreshTokens.$inferSelect;
/** Values required to insert a refresh token. */
export type NewRefreshToken = typeof refreshTokens.$inferInsert;

/** A consent row as selected. */
export type Consent = typeof consents.$inferSelect;
/** Values required to insert a consent. */
export type NewConsent = typeof consents.$inferInsert;

/** A `jti` replay ledger row as selected. */
export type JtiReplay = typeof jtiReplay.$inferSelect;
/** Values required to insert a `jti` replay ledger row. */
export type NewJtiReplay = typeof jtiReplay.$inferInsert;

/** An end user session row as selected. */
export type EndUserSession = typeof endUserSessions.$inferSelect;
/** Values required to insert an end user session. */
export type NewEndUserSession = typeof endUserSessions.$inferInsert;

/** A federation round-trip row as selected. */
export type FederationState = typeof federationStates.$inferSelect;
/** Values required to insert a federation round trip. */
export type NewFederationState = typeof federationStates.$inferInsert;
