/**
 * Endpoint configuration: the authorization servers a tenant runs.
 *
 * An endpoint is one SMART issuer in front of one FHIR base URL. Its capability
 * flags are stored as discrete boolean columns rather than a single JSONB blob,
 * deliberately: the set is closed by SMART App Launch 2.2.0, every flag is a
 * conformance claim published in `.well-known/smart-configuration`, and a
 * missing JSONB key would silently read as `false` - quietly withdrawing an
 * advertised capability. Discrete columns make each flag a `NOT NULL DEFAULT`
 * with a visible migration, and let the console filter on them in SQL.
 *
 * Author: John Grimes
 */

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

import { createdAt, timestamps } from "./columns.js";
import {
  endpointAuthModeEnum,
  endpointConsentModeEnum,
  endpointKeyAlgorithmEnum,
  endpointKeyStatusEnum,
  endpointStatusEnum,
} from "./enums.js";
import { tenants } from "./tenancy.js";

import type { LaunchContext } from "@signet/core";

/**
 * How an upstream OIDC provider's claims map onto Signet's user model.
 *
 * Each value is the name of a claim in the upstream ID token or userinfo
 * response; each key is the Signet field it populates.
 */
export interface IdpClaimMappings {
  /** Claim yielding a relative FHIR reference, e.g. `Practitioner/123`. */
  readonly fhirUser?: string;
  /** Claim yielding roles, as either an array or a space-delimited string. */
  readonly roles?: string;
  readonly displayName?: string;
  /** Further claims to copy verbatim into the user's attributes. */
  readonly attributes?: readonly string[];
}

/** A SMART authorization server issuer fronting one FHIR base URL. */
export const endpoints = pgTable(
  "endpoints",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    /** URL path segment, as in `/t/{tenant}/e/{slug}`. */
    slug: text("slug").notNull(),
    name: text("name").notNull(),
    description: text("description"),
    /** The BYO FHIR server's base URL, and the expected token `aud`. */
    fhirBaseUrl: text("fhir_base_url").notNull(),

    // Launch modes.
    supportsEhrLaunch: boolean("supports_ehr_launch").notNull().default(true),
    supportsStandaloneLaunch: boolean("supports_standalone_launch")
      .notNull()
      .default(true),
    supportsAuthorizePost: boolean("supports_authorize_post")
      .notNull()
      .default(false),

    // Client types.
    allowsPublicClients: boolean("allows_public_clients")
      .notNull()
      .default(true),
    allowsConfidentialSymmetricClients: boolean(
      "allows_confidential_symmetric_clients",
    )
      .notNull()
      .default(true),
    allowsConfidentialAsymmetricClients: boolean(
      "allows_confidential_asymmetric_clients",
    )
      .notNull()
      .default(true),

    // Single sign-on.
    supportsOpenIdConnect: boolean("supports_openid_connect")
      .notNull()
      .default(true),

    // UI integration.
    supportsPatientBanner: boolean("supports_patient_banner")
      .notNull()
      .default(true),
    supportsStyling: boolean("supports_styling").notNull().default(false),

    // Launch context.
    supportsEhrPatientContext: boolean("supports_ehr_patient_context")
      .notNull()
      .default(true),
    supportsEhrEncounterContext: boolean("supports_ehr_encounter_context")
      .notNull()
      .default(true),
    supportsStandalonePatientContext: boolean(
      "supports_standalone_patient_context",
    )
      .notNull()
      .default(true),
    supportsStandaloneEncounterContext: boolean(
      "supports_standalone_encounter_context",
    )
      .notNull()
      .default(false),

    // Permissions.
    supportsOfflineAccess: boolean("supports_offline_access")
      .notNull()
      .default(true),
    supportsOnlineAccess: boolean("supports_online_access")
      .notNull()
      .default(true),
    supportsPatientScopes: boolean("supports_patient_scopes")
      .notNull()
      .default(true),
    supportsUserScopes: boolean("supports_user_scopes").notNull().default(true),
    supportsV1Scopes: boolean("supports_v1_scopes").notNull().default(true),
    supportsV2Scopes: boolean("supports_v2_scopes").notNull().default(true),

    /** Enables `client_credentials` for SMART Backend Services. */
    supportsBackendServices: boolean("supports_backend_services")
      .notNull()
      .default(true),
    /** Dynamic registration is off unless an operator turns it on. */
    supportsDynamicRegistration: boolean("supports_dynamic_registration")
      .notNull()
      .default(false),

    /**
     * Advertised in `scopes_supported`. A Postgres array rather than JSONB so
     * that "which endpoints advertise this scope?" is an indexable containment
     * query instead of a JSON traversal.
     */
    scopesSupported: text("scopes_supported").array().notNull().default([]),

    /** User Access Brand bundle URL, published in discovery when set. */
    userAccessBrandBundle: text("user_access_brand_bundle"),
    userAccessBrandIdentifier: text("user_access_brand_identifier"),

    /** Access token lifetime in seconds. */
    accessTokenTtl: integer("access_token_ttl").notNull().default(300),
    /** Refresh token lifetime in seconds. */
    refreshTokenTtl: integer("refresh_token_ttl").notNull().default(2_592_000),

    authMode: endpointAuthModeEnum("auth_mode").notNull().default("local"),
    consentMode: endpointConsentModeEnum("consent_mode")
      .notNull()
      .default("always"),
    /**
     * Personas are only selectable when this is false. Defaulting to true means
     * a carelessly created endpoint is the safe kind, not the one that hands out
     * password-free logins.
     */
    isProduction: boolean("is_production").notNull().default(true),
    status: endpointStatusEnum("status").notNull().default("active"),

    ...timestamps(),
  },
  (table) => [
    uniqueIndex("endpoints_tenant_id_slug_unique").on(
      table.tenantId,
      table.slug,
    ),
    index("endpoints_tenant_id_idx").on(table.tenantId),
  ],
);

/** A signing key belonging to an endpoint, in one rotation state. */
export const endpointKeys = pgTable(
  "endpoint_keys",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    endpointId: uuid("endpoint_id")
      .notNull()
      .references(() => endpoints.id, { onDelete: "cascade" }),
    /** JWK `kid`, unique within the endpoint so JWKS entries never collide. */
    kid: text("kid").notNull(),
    algorithm: endpointKeyAlgorithmEnum("algorithm").notNull(),
    /** The public half, served verbatim from the endpoint's JWKS. */
    publicJwk: jsonb("public_jwk").$type<Record<string, unknown>>().notNull(),
    /**
     * The private half, AES-256-GCM envelope-encrypted under
     * `SIGNET_MASTER_KEY`. Held as text (base64) rather than `bytea` so a
     * logical dump stays human-transportable; no API ever returns it.
     */
    privateJwkEncrypted: text("private_jwk_encrypted").notNull(),
    status: endpointKeyStatusEnum("status").notNull().default("next"),
    ...createdAt(),
    activatedAt: timestamp("activated_at", { withTimezone: true }),
    retiredAt: timestamp("retired_at", { withTimezone: true }),
  },
  (table) => [
    uniqueIndex("endpoint_keys_endpoint_id_kid_unique").on(
      table.endpointId,
      table.kid,
    ),
    index("endpoint_keys_endpoint_id_status_idx").on(
      table.endpointId,
      table.status,
    ),
  ],
);

/** Upstream OIDC provider configuration for an endpoint in `oidc` auth mode. */
export const idpConfigs = pgTable("idp_configs", {
  /**
   * Primary key as well as foreign key: an endpoint federates to at most one
   * upstream provider, and making that structural removes the need to police
   * it in application code.
   */
  endpointId: uuid("endpoint_id")
    .primaryKey()
    .references(() => endpoints.id, { onDelete: "cascade" }),
  issuer: text("issuer").notNull(),
  /**
   * What to call the provider on the sign-in button.
   *
   * "Continue with St Elsewhere SSO" is a button somebody can act on; "Continue
   * with https://sso.example.org" is a URL an end user has no reason to recognise.
   * Nullable, and the login page falls back to neutral wording rather than
   * exposing the issuer.
   */
  displayName: text("display_name"),
  clientId: text("client_id").notNull(),
  /**
   * AES-256-GCM envelope-encrypted under `SIGNET_MASTER_KEY`. Signet must be
   * able to present this credential upstream, so it is encrypted rather than
   * hashed - the only category of secret here that is not one-way.
   */
  clientSecretEncrypted: text("client_secret_encrypted"),
  scopes: text("scopes").array().notNull().default(["openid", "profile"]),
  claimMappings: jsonb("claim_mappings")
    .$type<IdpClaimMappings>()
    .notNull()
    .default({}),
  /** When the upstream discovery document was last fetched. */
  discoveryCachedAt: timestamp("discovery_cached_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

/** An end user or persona able to authorise apps on one endpoint. */
export const endUsers = pgTable(
  "end_users",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    endpointId: uuid("endpoint_id")
      .notNull()
      .references(() => endpoints.id, { onDelete: "cascade" }),
    username: text("username").notNull(),
    /**
     * Argon2id PHC string, or null for a persona, which has no password by
     * design. Never a recoverable password.
     */
    passwordHash: text("password_hash"),
    /** Relative FHIR reference, e.g. `Practitioner/123`. */
    fhirUserReference: text("fhir_user_reference"),
    displayName: text("display_name").notNull(),
    roles: text("roles").array().notNull().default([]),
    /** Arbitrary attributes a policy may template from. */
    attributes: jsonb("attributes")
      .$type<Record<string, unknown>>()
      .notNull()
      .default({}),
    /**
     * Launch context pre-set for a persona, so a connectathon endpoint can hand
     * out a working patient context without an EHR. Kept separate from
     * `attributes` because it is a validated `LaunchContext`, not free-form.
     */
    defaultContext: jsonb("default_context").$type<LaunchContext>(),
    isPersona: boolean("is_persona").notNull().default(false),
    ...createdAt(),
    disabledAt: timestamp("disabled_at", { withTimezone: true }),
  },
  (table) => [
    uniqueIndex("end_users_endpoint_id_username_unique").on(
      table.endpointId,
      table.username,
    ),
    index("end_users_endpoint_id_idx").on(table.endpointId),
  ],
);

/** An endpoint row as selected. */
export type Endpoint = typeof endpoints.$inferSelect;
/** Values required to insert an endpoint. */
export type NewEndpoint = typeof endpoints.$inferInsert;

/** An endpoint signing key row as selected. */
export type EndpointKey = typeof endpointKeys.$inferSelect;
/** Values required to insert an endpoint signing key. */
export type NewEndpointKey = typeof endpointKeys.$inferInsert;

/** An upstream IdP configuration row as selected. */
export type IdpConfig = typeof idpConfigs.$inferSelect;
/** Values required to insert an upstream IdP configuration. */
export type NewIdpConfig = typeof idpConfigs.$inferInsert;

/** An end user row as selected. */
export type EndUser = typeof endUsers.$inferSelect;
/** Values required to insert an end user. */
export type NewEndUser = typeof endUsers.$inferInsert;
