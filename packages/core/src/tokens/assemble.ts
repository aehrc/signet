/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Assembly of token payloads and token endpoint responses.
 *
 * Every function here is pure: time, identifiers and the policy evaluation all
 * arrive as parameters, so the console's policy simulator can render exactly
 * what the server would issue.
 *
 * Author: John Grimes
 */

import { formatScopes, hasIdentityScope } from "../scopes/index.js";

import type {
  AccessTokenClaims,
  AccessTokenInput,
  IdTokenClaims,
  TokenIssuanceParameters,
  TokenResponse,
  TokenResponseInput,
} from "./types.js";
import type { EndpointKind } from "../endpointKind.js";
import type {
  EvaluationContext,
  EvaluationUser,
  PolicyEvaluation,
} from "../policy/types.js";
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

/**
 * The claims about the user that the granted identity scopes release.
 *
 * On a SMART endpoint, `fhirUser` releases the user's FHIR reference, and so
 * does `profile`, which SMART treats as a deprecated synonym for it. On an OAuth
 * endpoint the OpenID Connect standard claims are released instead: `profile`
 * gives `name` and `preferred_username`, and `email` gives `email` and
 * `email_verified` when the user has an email address. A claim with no value is
 * left out rather than sent empty.
 *
 * Shared by the ID token and so, through the claims recorded at issuance, by
 * UserInfo: the two cannot disagree about who the user is.
 *
 * @param kind - The kind of endpoint issuing the token.
 * @param user - The signed-in user, or null for a client acting for itself.
 * @param granted - The scopes actually granted.
 * @returns The identity claims to release, possibly none.
 * @see https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
 */
export function identityClaims(
  kind: EndpointKind,
  user: EvaluationUser | null,
  granted: readonly Scope[],
): Readonly<Record<string, unknown>> {
  if (user === null) {
    return {};
  }
  if (kind === "smart") {
    const fhirUser = user.fhirUser;
    if (fhirUser === null) {
      return {};
    }
    return {
      ...(hasIdentityScope(granted, "fhirUser") ? { fhirUser } : {}),
      ...(hasIdentityScope(granted, "profile") ? { profile: fhirUser } : {}),
    };
  }
  return {
    ...(hasIdentityScope(granted, "profile")
      ? {
          ...(user.displayName === null ? {} : { name: user.displayName }),
          preferred_username: user.username,
        }
      : {}),
    ...(hasIdentityScope(granted, "email") && user.email !== null
      ? { email: user.email, email_verified: user.emailVerified }
      : {}),
  };
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
    aud: context.endpoint.audience,
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
 * access token. Policy-emitted claims are deliberately not merged in - they
 * describe authorization, which belongs in the access token, not in an identity
 * assertion.
 *
 * @param input - The evaluation, its context, and the issuance parameters.
 * @returns The complete ID token payload.
 */
export function assembleIdTokenClaims(input: IdTokenInput): IdTokenClaims {
  const { evaluation, context, issuance } = input;
  const ttl = input.idTokenTtl ?? evaluation.accessTokenTtl;

  return {
    // Conditional claims are spread first so they can never displace a
    // registered claim, whatever ends up being derived.
    ...(issuance.nonce === undefined ? {} : { nonce: issuance.nonce }),
    ...(issuance.authTime === undefined
      ? {}
      : { auth_time: issuance.authTime }),
    ...identityClaims(
      context.endpoint.kind,
      context.user,
      evaluation.grantedScopes,
    ),
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
