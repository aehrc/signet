/**
 * Author: John Grimes
 */

import { deriveCapabilities } from "./capabilities.js";
import { endpointUrls, normaliseIssuer } from "./endpoints.js";

import type {
  DiscoveryRuleOptions,
  EndpointCapabilityConfig,
  OpenIdConfiguration,
  SmartConfiguration,
  TokenEndpointAuthMethod,
} from "./types.js";

/**
 * The only PKCE challenge method Signet will ever advertise or accept.
 *
 * SMART requires `S256` and forbids `plain`, so this is a constant rather than
 * anything derived from configuration - there is no supported deployment in
 * which downgrading to `plain` is a legitimate choice.
 */
const CODE_CHALLENGE_METHODS: readonly "S256"[] = ["S256"];

/**
 * The signing algorithms SMART names, used when an endpoint has published no key.
 *
 * An endpoint with keys advertises *those* algorithms instead - see
 * {@link buildOpenIdConfiguration}. A document that named an algorithm no
 * published key uses would tell a relying party to expect something it will never
 * see, and one that omitted the algorithm actually in use would have a strict
 * verifier reject every token.
 *
 * @see https://hl7.org/fhir/smart-app-launch/client-confidential-asymmetric.html
 */
const DEFAULT_ID_TOKEN_SIGNING_ALGS: readonly string[] = ["RS384", "ES384"];

/** The claims Signet puts in an ID token, advertised for OIDC discovery. */
const CLAIMS_SUPPORTED: readonly string[] = [
  "sub",
  "iss",
  "aud",
  "exp",
  "iat",
  "fhirUser",
  "profile",
];

/** Signet only ever issues authorization codes, never implicit tokens. */
const RESPONSE_TYPES: readonly string[] = ["code"];

/** True when the endpoint supports at least one interactive launch mode. */
function supportsAnyLaunch(config: EndpointCapabilityConfig): boolean {
  return config.supportsEhrLaunch || config.supportsStandaloneLaunch;
}

/**
 * Derives the credential-based client authentication methods.
 *
 * Public clients authenticate with PKCE rather than a credential, so they
 * contribute nothing here: an endpoint admitting only public clients yields an
 * empty list, and the caller omits the field entirely.
 */
function smartAuthMethods(
  config: EndpointCapabilityConfig,
): readonly TokenEndpointAuthMethod[] {
  const methods: TokenEndpointAuthMethod[] = [];
  if (config.allowsConfidentialSymmetricClients) {
    methods.push("client_secret_basic", "client_secret_post");
  }
  if (config.allowsConfidentialAsymmetricClients) {
    methods.push("private_key_jwt");
  }
  return methods;
}

/**
 * The same list for OpenID Connect discovery, which additionally has a value for
 * "authenticates with no credential".
 *
 * SMART's own enumeration is only the three credential-based methods, so `none`
 * must not leak into `smart-configuration`. OIDC does define it, and a
 * public-client endpoint that advertised an empty array there would read as "no
 * client may authenticate at all".
 */
function oidcAuthMethods(
  config: EndpointCapabilityConfig,
): readonly TokenEndpointAuthMethod[] {
  const methods = smartAuthMethods(config);
  return config.allowsPublicClients ? ["none", ...methods] : methods;
}

/**
 * Derives the OAuth grant types the endpoint will honour.
 *
 * `authorization_code` follows from supporting a launch mode; SMART Backend
 * Services is what brings `client_credentials`.
 */
function smartGrantTypes(
  config: EndpointCapabilityConfig,
): readonly ("authorization_code" | "client_credentials")[] {
  const grants: ("authorization_code" | "client_credentials")[] = [];
  if (supportsAnyLaunch(config)) {
    grants.push("authorization_code");
  }
  if (config.supportsBackendServices) {
    grants.push("client_credentials");
  }
  return grants;
}

/**
 * Builds the `.well-known/smart-configuration` document.
 *
 * Conditional fields are omitted entirely rather than emitted as `undefined`,
 * because a client reading `"authorization_endpoint": null` would have no way
 * to tell a deliberately unsupported feature from a broken server.
 *
 * @param config - The endpoint configuration.
 * @param rules - What the endpoint's opt-in rules say. Omitted means none of
 *   them are in force, which is the refusing default: an endpoint that has not
 *   been asked about its trust anchor advertises no registration endpoint.
 * @returns The document to serve.
 * @see https://hl7.org/fhir/smart-app-launch/conformance.html
 */
export function buildSmartConfiguration(
  config: EndpointCapabilityConfig,
  rules: DiscoveryRuleOptions = {},
): SmartConfiguration {
  const urls = endpointUrls(config.issuer);
  const methods = smartAuthMethods(config);
  return {
    // REQUIRED for sso-openid-connect. Left out otherwise so that an endpoint
    // which issues no ID tokens does not look like an OIDC provider.
    ...(config.supportsOpenIdConnect
      ? { issuer: normaliseIssuer(config.issuer) }
      : {}),
    // Always advertised: even a non-OIDC endpoint signs access tokens, and
    // resource servers need the keys to verify them.
    jwks_uri: urls.jwks,
    ...(supportsAnyLaunch(config)
      ? { authorization_endpoint: urls.authorization }
      : {}),
    token_endpoint: urls.token,
    grant_types_supported: smartGrantTypes(config),
    ...(methods.length > 0
      ? { token_endpoint_auth_methods_supported: methods }
      : {}),
    // From the trust anchor rule, never from a capability column: this address is
    // served only by an endpoint that names an anchor, and every other endpoint
    // answers 404 there.
    ...(rules.acceptsVouchedRegistration === true
      ? { registration_endpoint: urls.registration }
      : {}),
    // From the ticket issuer rule, and only when it names a type. An endpoint
    // with no rule refuses the exchange grant, and one whose rule names no type
    // refuses every ticket - neither has anything to advertise.
    ...(rules.permissionTicketTypes !== undefined &&
    rules.permissionTicketTypes.length > 0
      ? { smart_permission_ticket_types_supported: rules.permissionTicketTypes }
      : {}),
    ...(config.scopesSupported.length > 0
      ? { scopes_supported: config.scopesSupported }
      : {}),
    response_types_supported: RESPONSE_TYPES,
    management_endpoint: urls.management,
    introspection_endpoint: urls.introspection,
    revocation_endpoint: urls.revocation,
    capabilities: deriveCapabilities(config),
    code_challenge_methods_supported: CODE_CHALLENGE_METHODS,
    ...(config.userAccessBrandBundle === undefined
      ? {}
      : { user_access_brand_bundle: config.userAccessBrandBundle }),
    ...(config.userAccessBrandIdentifier === undefined
      ? {}
      : { user_access_brand_identifier: config.userAccessBrandIdentifier }),
  };
}

/**
 * Builds the `.well-known/openid-configuration` document.
 *
 * Resource servers - Pathling among them - assemble their own SMART
 * configuration by merging fields out of this document, so it is filled in
 * completely even for endpoints whose primary purpose is not single sign-on.
 *
 * @param config - The endpoint configuration.
 * @param options - What the document should say about this endpoint's keys, and
 *   what its opt-in rules say.
 * @param options.signingAlgorithms - The algorithms of the keys the endpoint
 *   publishes, in advertisement order. Omit for an endpoint with none, which
 *   falls back to the pair SMART names.
 * @returns The document to serve.
 * @see https://openid.net/specs/openid-connect-discovery-1_0.html
 */
export function buildOpenIdConfiguration(
  config: EndpointCapabilityConfig,
  options: DiscoveryRuleOptions & {
    readonly signingAlgorithms?: readonly string[];
  } = {},
): OpenIdConfiguration {
  const urls = endpointUrls(config.issuer);
  const grants: string[] = [...smartGrantTypes(config)];
  // Unlike smart-configuration, OIDC discovery expects the complete grant type
  // list, and a refresh token is only issued when one of these scopes is on
  // offer.
  if (config.supportsOfflineAccess || config.supportsOnlineAccess) {
    grants.push("refresh_token");
  }
  return {
    issuer: normaliseIssuer(config.issuer),
    authorization_endpoint: urls.authorization,
    token_endpoint: urls.token,
    jwks_uri: urls.jwks,
    ...(config.supportsOpenIdConnect
      ? { userinfo_endpoint: urls.userinfo }
      : {}),
    // The same rule as the SMART document above, and deliberately the same
    // answer: a resource server that merges from this one must not be told about
    // a registration endpoint the other does not advertise.
    ...(options.acceptsVouchedRegistration === true
      ? { registration_endpoint: urls.registration }
      : {}),
    introspection_endpoint: urls.introspection,
    revocation_endpoint: urls.revocation,
    scopes_supported: config.scopesSupported,
    response_types_supported: RESPONSE_TYPES,
    grant_types_supported: grants,
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported:
      options.signingAlgorithms === undefined ||
      options.signingAlgorithms.length === 0
        ? DEFAULT_ID_TOKEN_SIGNING_ALGS
        : options.signingAlgorithms,
    token_endpoint_auth_methods_supported: oidcAuthMethods(config),
    code_challenge_methods_supported: CODE_CHALLENGE_METHODS,
    claims_supported: CLAIMS_SUPPORTED,
  };
}
