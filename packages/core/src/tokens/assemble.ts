/**
 * Assembly of token payloads and token endpoint responses.
 *
 * Every function here is pure: time, identifiers and the policy evaluation all
 * arrive as parameters, so the console's policy simulator can render exactly
 * what the server would issue.
 */

import { formatScopes } from "../scopes/index.js";

import type {
  AccessTokenClaims,
  AccessTokenInput,
  IdTokenClaims,
  TokenIssuanceParameters,
  TokenResponse,
  TokenResponseInput,
} from "./types.js";
import type { EvaluationContext, PolicyEvaluation } from "../policy/types.js";
import type { Scope } from "../scopes/types.js";

/**
 * Standard OAuth token response fields a policy must never be able to set.
 *
 * A context rule that could overwrite `access_token` or widen the advertised
 * `scope` would be a privilege escalation, so these names are stripped from
 * policy-emitted parameters before merging.
 */
const RESERVED_RESPONSE_PARAMETERS: ReadonlySet<string> = new Set([
  "access_token",
  "token_type",
  "expires_in",
  "scope",
  "id_token",
  "refresh_token",
]);

/** True when the granted scopes include the given identity scope. */
function hasIdentityScope(
  granted: readonly Scope[],
  name: "openid" | "fhirUser" | "profile",
): boolean {
  return granted.some(
    (scope) => scope.kind === "identity" && scope.name === name,
  );
}

/**
 * Assembles the claims for a signed access token.
 *
 * Policy-emitted claims are merged *underneath* the registered claims. This is
 * a security boundary rather than a stylistic choice: endpoint configuration is
 * authored by tenant administrators, and a policy that could rewrite `iss`,
 * `aud`, `sub`, `exp` or `scope` would be able to mint a token for another
 * audience or with an unbounded lifetime.
 *
 * @param input - The evaluation, its context, and the server-chosen issuance
 *   parameters.
 * @returns The complete access token payload.
 */
export function assembleAccessTokenClaims(
  input: AccessTokenInput,
): AccessTokenClaims {
  const { evaluation, context, issuance } = input;

  return {
    ...evaluation.claims,
    iss: context.endpoint.issuer,
    // The resource server, not the client: a SMART access token is presented to
    // the BYO FHIR server, which validates itself as the audience.
    aud: context.endpoint.fhirBaseUrl,
    sub: issuance.subject,
    exp: issuance.issuedAt + evaluation.accessTokenTtl,
    iat: issuance.issuedAt,
    jti: issuance.jti,
    scope: formatScopes(evaluation.grantedScopes),
    client_id: context.client.clientId,
  };
}

/**
 * Inputs for assembling ID token claims.
 *
 * Mirrors {@link AccessTokenInput}; the evaluation is needed for the granted
 * scopes, which decide whether the identity claims are released.
 */
export interface IdTokenInput {
  readonly evaluation: PolicyEvaluation;
  readonly context: EvaluationContext;
  readonly issuance: TokenIssuanceParameters;
  /**
   * ID token lifetime in seconds. Defaults to the access token lifetime.
   *
   * OpenID Connect does not tie the two together, and a policy document has no
   * field for it, so a caller that wants them to differ passes this explicitly.
   */
  readonly idTokenTtl?: number;
}

/**
 * Assembles the claims for a signed OpenID Connect ID token.
 *
 * Unlike the access token, an ID token is addressed to the *client*: its `aud`
 * is the client id, and a resource server must never accept one in place of an
 * access token. Policy-emitted claims are deliberately not merged in — they
 * describe authorization, which belongs in the access token, not in an identity
 * assertion.
 *
 * @param input - The evaluation, its context, and the issuance parameters.
 * @returns The complete ID token payload.
 */
export function assembleIdTokenClaims(input: IdTokenInput): IdTokenClaims {
  const { evaluation, context, issuance } = input;
  const ttl = input.idTokenTtl ?? evaluation.accessTokenTtl;
  const fhirUser = context.user?.fhirUser ?? null;
  const granted = evaluation.grantedScopes;

  return {
    // Conditional claims are spread first so they can never displace a
    // registered claim, whatever ends up being derived.
    ...(issuance.nonce === undefined ? {} : { nonce: issuance.nonce }),
    ...(issuance.authTime === undefined
      ? {}
      : { auth_time: issuance.authTime }),
    ...(fhirUser !== null && hasIdentityScope(granted, "fhirUser")
      ? { fhirUser }
      : {}),
    // SMART treats `profile` as a deprecated synonym for `fhirUser`, so it
    // carries the same relative reference when that scope was granted.
    ...(fhirUser !== null && hasIdentityScope(granted, "profile")
      ? { profile: fhirUser }
      : {}),
    iss: context.endpoint.issuer,
    aud: context.client.clientId,
    sub: issuance.subject,
    exp: issuance.issuedAt + ttl,
    iat: issuance.issuedAt,
    jti: issuance.jti,
    azp: context.client.clientId,
  };
}

/**
 * Drops the reserved OAuth field names from policy-emitted parameters.
 *
 * @param parameters - Launch context and other policy-emitted parameters.
 */
function withoutReservedParameters(
  parameters: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(parameters).filter(
      ([name]) => !RESERVED_RESPONSE_PARAMETERS.has(name),
    ),
  );
}

/**
 * Assembles the token endpoint response body.
 *
 * Launch context parameters are merged in, but the standard OAuth fields are
 * always the server's. `id_token` and `refresh_token` are omitted entirely when
 * there is none, rather than serialised as `null` or `undefined`.
 *
 * @param input - The issued token material and the parameters to accompany it.
 * @returns The response body, ready to serialise as JSON.
 */
export function assembleTokenResponse(
  input: TokenResponseInput,
): TokenResponse {
  return {
    ...withoutReservedParameters(input.contextParams),
    access_token: input.accessToken,
    token_type: "Bearer",
    expires_in: input.expiresIn,
    scope: input.scope,
    ...(input.idToken === undefined ? {} : { id_token: input.idToken }),
    ...(input.refreshToken === undefined
      ? {}
      : { refresh_token: input.refreshToken }),
  };
}
