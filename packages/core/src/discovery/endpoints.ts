/**
 * Endpoint URL derivation.
 *
 * Every URL Signet advertises is derived from the tenant's issuer, so the
 * discovery documents, the token `iss` claim and the routes the server mounts
 * can never disagree about where something lives.
 *
 * Author: John Grimes
 */

/** Every endpoint URL Signet derives from a tenant's issuer. */
export interface EndpointUrls {
  readonly authorization: string;
  readonly token: string;
  readonly jwks: string;
  readonly introspection: string;
  readonly revocation: string;
  readonly userinfo: string;
  readonly registration: string;
  readonly management: string;
  readonly launchContext: string;
  readonly smartConfiguration: string;
  readonly openIdConfiguration: string;
}

/**
 * Strips trailing slashes from an issuer so that joining a path onto it cannot
 * produce a double slash.
 *
 * The normalised form is also the value advertised as `issuer` and minted into
 * the token `iss` claim: OAuth issuer identifiers are compared as exact
 * strings, so a stray trailing slash in configuration must not leak into one
 * document and not another.
 *
 * @param issuer - The configured issuer, with or without a trailing slash.
 */
export function normaliseIssuer(issuer: string): string {
  return issuer.replace(/\/+$/, "");
}

/**
 * Derives the full set of endpoint URLs for an issuer.
 *
 * @param issuer - The tenant's issuer identifier, e.g.
 *   `https://signet.example.com/t/acme`.
 */
export function endpointUrls(issuer: string): EndpointUrls {
  const base = normaliseIssuer(issuer);
  return {
    authorization: `${base}/authorize`,
    token: `${base}/token`,
    jwks: `${base}/jwks`,
    introspection: `${base}/introspect`,
    revocation: `${base}/revoke`,
    userinfo: `${base}/userinfo`,
    registration: `${base}/register`,
    management: `${base}/manage`,
    launchContext: `${base}/launch-context`,
    smartConfiguration: `${base}/.well-known/smart-configuration`,
    openIdConfiguration: `${base}/.well-known/openid-configuration`,
  };
}
