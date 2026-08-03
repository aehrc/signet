/**
 * Discovery document types.
 *
 * @see https://hl7.org/fhir/smart-app-launch/conformance.html
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
 * `openid-configuration` — advertising an empty array instead would read as "no
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

  /** Enables the dynamic registration endpoint. Off by default. */
  readonly supportsDynamicRegistration: boolean;

  readonly userAccessBrandBundle?: string;
  readonly userAccessBrandIdentifier?: string;
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
