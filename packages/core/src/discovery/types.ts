/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Discovery document types.
 *
 * @see https://hl7.org/fhir/smart-app-launch/conformance.html
 *
 * Author: John Grimes
 */

/** Every SMART capability string defined by SMART App Launch 2.2.0. */
export type SmartCapability =
  // Launch modes
  | "launch-ehr"
  | "launch-standalone"
  // Authorization methods
  | "authorize-post"
  // Client types
  | "client-public"
  | "client-confidential-symmetric"
  | "client-confidential-asymmetric"
  // Single sign-on
  | "sso-openid-connect"
  // Launch context: UI integration
  | "context-banner"
  | "context-style"
  // Launch context: EHR launch
  | "context-ehr-patient"
  | "context-ehr-encounter"
  // Launch context: standalone launch
  | "context-standalone-patient"
  | "context-standalone-encounter"
  // Permissions
  | "permission-offline"
  | "permission-online"
  | "permission-patient"
  | "permission-user"
  | "permission-v1"
  | "permission-v2";

/**
 * OAuth client authentication methods advertised at the token endpoint.
 *
 * `none` is the OpenID Connect value for a public client, which authenticates
 * with PKCE rather than a credential. SMART's own list omits it, but an endpoint
 * that allows only public clients has to be able to say so in its
 * `openid-configuration` - advertising an empty array instead would read as "no
 * client may authenticate".
 */
export type TokenEndpointAuthMethod =
  "none" | "client_secret_post" | "client_secret_basic" | "private_key_jwt";

/**
 * How an endpoint is configured. The discovery documents and the `capabilities`
 * array are derived from this, so what Signet advertises cannot drift from what
 * it actually does.
 */
export interface EndpointCapabilityConfig {
  readonly issuer: string;
  readonly fhirBaseUrl: string;

  readonly supportsEhrLaunch: boolean;
  readonly supportsStandaloneLaunch: boolean;
  readonly supportsAuthorizePost: boolean;

  readonly allowsPublicClients: boolean;
  readonly allowsConfidentialSymmetricClients: boolean;
  readonly allowsConfidentialAsymmetricClients: boolean;

  readonly supportsOpenIdConnect: boolean;

  readonly supportsPatientBanner: boolean;
  readonly supportsStyling: boolean;

  readonly supportsEhrPatientContext: boolean;
  readonly supportsEhrEncounterContext: boolean;
  readonly supportsStandalonePatientContext: boolean;
  readonly supportsStandaloneEncounterContext: boolean;

  readonly supportsOfflineAccess: boolean;
  readonly supportsOnlineAccess: boolean;
  readonly supportsPatientScopes: boolean;
  readonly supportsUserScopes: boolean;
  readonly supportsV1Scopes: boolean;
  readonly supportsV2Scopes: boolean;

  /** Enables the `client_credentials` grant for SMART Backend Services. */
  readonly supportsBackendServices: boolean;

  /** Advertised in `scopes_supported`. */
  readonly scopesSupported: readonly string[];

  /**
   * Enables the developer portal, where a human reviews each request.
   *
   * Not the registration endpoint, despite the name. `registration_endpoint` is
   * advertised only when the endpoint names a trust anchor, which is a rule in a
   * table of its own rather than a column here - see
   * {@link DiscoveryRuleOptions.acceptsVouchedRegistration}.
   */
  readonly supportsDynamicRegistration: boolean;

  readonly userAccessBrandBundle?: string;
  readonly userAccessBrandIdentifier?: string;
}

/**
 * What the endpoint's opt-in rules say, for the fields that come from a rule
 * rather than from a capability column.
 *
 * Separate from {@link EndpointCapabilityConfig} because the rules live in their
 * own tables: the capability config is a copy of the endpoint row, and folding a
 * rule into it would mean either a lie or a second lookup at every call site that
 * only wants the columns. Every member is optional and every default is the
 * refusing one, so a caller that has not looked a rule up advertises nothing.
 */
export interface DiscoveryRuleOptions {
  /**
   * Whether the endpoint names a trust anchor, and so serves `/register`.
   *
   * Absent means no: an endpoint with no anchor answers 404 there, and a document
   * advertising the address anyway would be a promise nothing keeps.
   */
  readonly acceptsVouchedRegistration?: boolean;
  /**
   * The permission ticket types the endpoint's ticket issuer rule accepts.
   *
   * Absent means none, and so does empty: an endpoint with no rule refuses the
   * token exchange grant, and a rule that names no type accepts no ticket.
   * Advertising an empty array would say "exchange is supported" and then refuse
   * every ticket presented.
   */
  readonly permissionTicketTypes?: readonly string[];
}

/**
 * The `.well-known/smart-configuration` document.
 *
 * `authorization_endpoint` is required when either launch mode is supported;
 * `issuer` and `jwks_uri` are required when `sso-openid-connect` is.
 */
export interface SmartConfiguration {
  readonly issuer?: string;
  readonly jwks_uri?: string;
  readonly authorization_endpoint?: string;
  readonly token_endpoint: string;
  readonly grant_types_supported: readonly (
    "authorization_code" | "client_credentials"
  )[];
  readonly token_endpoint_auth_methods_supported?: readonly TokenEndpointAuthMethod[];
  readonly registration_endpoint?: string;
  /**
   * The permission ticket types honoured at the token endpoint.
   *
   * Present only on an endpoint that names a ticket issuer, which is what makes
   * it a promise rather than a hope: everywhere else the exchange grant is
   * refused as unsupported.
   *
   * @see https://build.fhir.org/ig/HL7/smart-app-launch/permission-tickets.html
   */
  readonly smart_permission_ticket_types_supported?: readonly string[];
  readonly scopes_supported?: readonly string[];
  readonly response_types_supported?: readonly string[];
  readonly management_endpoint?: string;
  readonly introspection_endpoint?: string;
  readonly revocation_endpoint?: string;
  readonly capabilities: readonly SmartCapability[];
  readonly code_challenge_methods_supported: readonly "S256"[];
  readonly associated_endpoints?: readonly {
    readonly url: string;
    readonly capabilities: readonly string[];
  }[];
  readonly user_access_brand_bundle?: string;
  readonly user_access_brand_identifier?: string;
}

/**
 * The `.well-known/openid-configuration` document.
 *
 * Pathling and other resource servers build their own SMART configuration by
 * merging from this, so it must be present and correct even for endpoints whose
 * primary use is not OpenID Connect.
 */
export interface OpenIdConfiguration {
  readonly issuer: string;
  readonly authorization_endpoint: string;
  readonly token_endpoint: string;
  readonly jwks_uri: string;
  readonly userinfo_endpoint?: string;
  readonly registration_endpoint?: string;
  readonly introspection_endpoint?: string;
  readonly revocation_endpoint?: string;
  readonly scopes_supported: readonly string[];
  readonly response_types_supported: readonly string[];
  readonly grant_types_supported: readonly string[];
  readonly subject_types_supported: readonly "public"[];
  readonly id_token_signing_alg_values_supported: readonly string[];
  readonly token_endpoint_auth_methods_supported: readonly TokenEndpointAuthMethod[];
  readonly code_challenge_methods_supported: readonly "S256"[];
  readonly claims_supported?: readonly string[];
}
