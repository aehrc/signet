/**
 * What a policy would produce, without producing it.
 *
 * The console's policy editor is only trustworthy if what it shows is what the
 * token endpoint would mint. This composes the same three calls the server's
 * issuance path makes — evaluate, assemble the access token, assemble the ID token
 * — in the same order over the same context, and returns the results decoded rather
 * than signed.
 *
 * Deliberately in `@signet/core` rather than in the console or the admin API. A
 * simulator that reimplemented any part of the composition would eventually agree
 * with itself and disagree with the server, and the failure would look like the
 * policy engine being wrong rather than the preview being wrong.
 *
 * Nothing here signs, stores or issues. There is no key material in scope, no
 * refresh token, and the `jti` is whatever the caller passes: a simulation is a
 * pure function of a policy and a context, which is what makes it safe to run on
 * every keystroke.
 */

import {
  assembleAccessTokenClaims,
  assembleIdTokenClaims,
} from "./assemble.js";
import { evaluatePolicy } from "../policy/evaluate.js";
import { formatScopes } from "../scopes/index.js";

import type {
  AccessTokenClaims,
  IdTokenClaims,
  TokenIssuanceParameters,
} from "./types.js";
import type {
  EvaluationContext,
  PolicyDocument,
  PolicyEvaluation,
} from "../policy/types.js";
import type { Scope } from "../scopes/types.js";

/** What a simulation needs beyond the policy and the context. */
export interface SimulationInput {
  readonly policy: PolicyDocument;
  readonly context: EvaluationContext;
  readonly issuance: TokenIssuanceParameters;
  /**
   * Whether the endpoint is configured for OpenID Connect.
   *
   * Both this and a granted `openid` scope are required before an ID token is
   * shown, exactly as at issuance: a policy may grant `openid` on an endpoint whose
   * discovery document says it is not an OIDC provider, and the document is the
   * promise Signet has to keep.
   */
  readonly supportsOpenIdConnect?: boolean;
}

/** Everything a simulation can say about a hypothetical token. */
export interface SimulationResult {
  /** Granted scopes, in the form they would appear in the `scope` claim. */
  readonly scope: string;
  readonly evaluation: PolicyEvaluation;
  readonly accessTokenClaims: AccessTokenClaims;
  /** Null when no ID token would be issued. */
  readonly idTokenClaims: IdTokenClaims | null;
  /**
   * Parameters the token response would carry alongside the standard fields.
   *
   * The standard fields themselves are not included: `access_token` and
   * `refresh_token` do not exist in a simulation, and `expires_in` and `scope` are
   * reported separately so the console need not dig them out of a merged object.
   */
  readonly responseParameters: Readonly<Record<string, unknown>>;
  readonly accessTokenTtl: number;
  readonly refreshTokenTtl: number;
  /** Whether a refresh token would accompany the access token. */
  readonly wouldIssueRefreshToken: boolean;
}

/** True when the granted scopes include the named identity scope. */
function hasIdentityScope(
  granted: readonly Scope[],
  name: "openid" | "fhirUser" | "profile",
): boolean {
  return granted.some(
    (scope) => scope.kind === "identity" && scope.name === name,
  );
}

/**
 * Evaluates a policy and assembles the tokens it would authorise.
 *
 * @param input - The policy, the context to evaluate it against, and the values
 *   the server would supply at issuance.
 */
export function simulateIssuance(input: SimulationInput): SimulationResult {
  const evaluation = evaluatePolicy(input.policy, input.context);
  const granted = evaluation.grantedScopes;

  const wantsIdToken =
    (input.supportsOpenIdConnect ?? true) &&
    hasIdentityScope(granted, "openid") &&
    input.context.user !== null;

  return {
    scope: formatScopes(granted),
    evaluation,
    accessTokenClaims: assembleAccessTokenClaims({
      evaluation,
      context: input.context,
      issuance: input.issuance,
    }),
    idTokenClaims: wantsIdToken
      ? assembleIdTokenClaims({
          evaluation,
          context: input.context,
          issuance: input.issuance,
        })
      : null,
    responseParameters: evaluation.contextParams,
    accessTokenTtl: evaluation.accessTokenTtl,
    refreshTokenTtl: evaluation.refreshTokenTtl,
    // A backend service never gets a refresh token, whatever the policy granted:
    // SMART Backend Services forbids it, and the server refuses one too.
    wouldIssueRefreshToken:
      input.context.grantType !== "client_credentials" &&
      granted.some((scope) => scope.kind === "refresh"),
  };
}
