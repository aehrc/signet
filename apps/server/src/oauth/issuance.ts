/**
 * Minting tokens. Every grant ends here, and only here.
 *
 * All three grants converge on this module rather than each assembling its own
 * response, because the interesting decisions are identical across them and
 * duplicating any one of them would eventually mean two answers to the same
 * question. In particular: which policy governs the token, whether the policy
 * granted anything at all, which key signs it, and what the `aud` is. A
 * `client_credentials` grant that resolved its policy differently from a
 * `refresh_token` grant would be a privilege-escalation bug that no single test
 * would catch.
 *
 * Two refusals here are deliberately *server* errors rather than client errors.
 * An endpoint with no published policy and an endpoint with no active signing key
 * are both misconfigurations, and answering `invalid_grant` would tell the app to
 * stop retrying and blame its own credential. The one thing this module will never
 * do is invent a permissive default for a missing policy.
 *
 * Author: John Grimes
 */

import {
  assembleAccessTokenClaims,
  assembleIdTokenClaims,
  assembleTokenResponse,
  describeVouching,
  evaluatePolicy,
  formatScopes,
} from "@signet/core";
import {
  generateOpaqueToken,
  getEffectivePolicy,
  hashToken,
  issueRefreshToken,
  recordAccessToken,
  redeemAndRotateRefreshToken,
  redeemRefreshToken,
  withTenantScope,
} from "@signet/db";

import { buildEvaluationContext } from "./evaluationContext.js";
import { loadSigningKey, signClaims } from "../keys/signing.js";

import type { ServerContext, ResolvedIssuerContext } from "../context.js";
import type {
  EvaluationClient,
  EvaluationUser,
  GrantType,
  LaunchContext,
  PolicyEvaluation,
  Scope,
  TokenResponse,
} from "@signet/core";
import type {
  ClientScope,
  EffectivePolicy,
  RefreshTokenRefusal,
} from "@signet/db";

/** Everything an issuance needs that the grant handler has already established. */
export interface IssuanceRequest {
  readonly issuerContext: ResolvedIssuerContext;
  readonly clientScope: ClientScope;
  readonly client: EvaluationClient;
  /** Null for a backend service, which has no end user. */
  readonly user: EvaluationUser | null;
  readonly grantType: GrantType;
  /** Scopes to evaluate, already parsed and normalised. */
  readonly requested: readonly Scope[];
  readonly launchContext: LaunchContext;
  /** The `sub` claim: the end user's id, or the client id for a backend service. */
  readonly subject: string;
  /**
   * When the client's vouching lapses, or null for a client nobody vouched for.
   *
   * Required rather than optional, so every grant has to state it and a new grant
   * cannot forget to. That is the whole enforcement: a trust anchor's registration
   * expires, and the expiry has to stop the client obtaining a token by *any*
   * grant, including a refresh of a token issued while the vouching was live.
   * Checking it here rather than in each grant is what makes "any" true.
   */
  readonly vouchingExpiresAt: Date | null;
  /**
   * A ceiling on the access token's lifetime, in seconds.
   *
   * For a grant whose authorisation expires before the endpoint's own token
   * lifetime would - a permission ticket exchange, whose token must not outlive
   * the ticket that authorised it. Applied to the evaluation rather than to the
   * response, so the signed `exp` and the reported `expires_in` are the same
   * number: capping only the response would advertise a short life for a token
   * that a resource server would keep accepting for an hour.
   *
   * Absent means the policy's own lifetime stands, which is every other grant.
   */
  readonly accessTokenTtlCeiling?: number;
  /** Copied into the ID token when the authorization carried one. */
  readonly nonce?: string;
  /** When the end user authenticated, as seconds since the epoch. */
  readonly authTime?: number;
  /**
   * The digest of the refresh token being rotated, for a `refresh_token` grant.
   *
   * Its presence means the presented token is claimed here and its successor
   * joins its family - which is what makes reuse of the predecessor detectable.
   * The claim happens inside this module rather than in the grant handler so that
   * claiming and replacing are one transaction: a failure between them rolls the
   * claim back, and the client retries with the token it still holds instead of
   * being logged out by a transient database error.
   */
  readonly rotate?: { readonly tokenHash: string };
}

/** Why an issuance could not proceed. */
export type IssuanceRefusal =
  /** The client was vouched for by a trust anchor, and that vouching has lapsed. */
  | "vouching-expired"
  /** The endpoint has no published policy and the client has no override. */
  | "no-policy"
  /** The endpoint has no active signing key. */
  | "no-signing-key"
  /** The policy granted none of the requested scopes. */
  | "nothing-granted"
  /** The refresh token being rotated could not be claimed. */
  | "refresh-token-unusable";

/** A minted token set, with the evaluation that produced it. */
export interface IssuedTokens {
  readonly response: TokenResponse;
  readonly evaluation: PolicyEvaluation;
  readonly policy: EffectivePolicy;
  /** The access token's `jti`, for the audit event. */
  readonly jti: string;
  readonly grantedScopes: string;
}

/** The outcome of an issuance. */
export type IssuanceResult =
  | { readonly ok: true; readonly issued: IssuedTokens }
  | {
      readonly ok: false;
      readonly reason: Exclude<IssuanceRefusal, "refresh-token-unusable">;
    }
  | {
      readonly ok: false;
      readonly reason: "refresh-token-unusable";
      readonly refresh: RefreshTokenRefusal;
      /** How many family members the reuse response revoked. Non-zero only on reuse. */
      readonly familyRevoked: number;
    };

/** True when the granted scopes contain the named identity scope. */
function hasIdentityScope(
  granted: readonly Scope[],
  name: "openid" | "fhirUser" | "profile",
): boolean {
  return granted.some(
    (scope) => scope.kind === "identity" && scope.name === name,
  );
}

/**
 * The refresh scope the policy granted, if it granted one.
 *
 * `offline_access` and `online_access` differ in intent - one survives the end of
 * the user's session and one does not - but both mean "issue a refresh token", so
 * either is sufficient here. Which was granted is recorded on the token's scope
 * string, so the distinction survives for the management page to act on.
 */
function grantsRefreshToken(granted: readonly Scope[]): boolean {
  return granted.some((scope) => scope.kind === "refresh");
}

/**
 * Evaluates the policy and mints whatever it authorised.
 *
 * @param context - The server's dependencies.
 * @param request - What the grant handler established about the authorization.
 */
export async function issueTokens(
  context: ServerContext,
  request: IssuanceRequest,
): Promise<IssuanceResult> {
  const { issuerContext, clientScope } = request;

  // Before the policy is even read. A client whose vouching has lapsed obtains no
  // token by any grant, and the cheapest possible refusal is the right one: this
  // is not a policy decision, it is the registration having ended.
  if (describeVouching(request.vouchingExpiresAt, context.clock()).expired) {
    return { ok: false, reason: "vouching-expired" };
  }

  const policy = await withTenantScope(context.db, clientScope, (bound) =>
    getEffectivePolicy(bound),
  );
  if (policy === undefined) {
    return { ok: false, reason: "no-policy" };
  }

  // Built once and reused for both the evaluation and the claim assembly. The
  // console's simulator renders a token from the same pair of calls over the same
  // context, and a second construction here is a second thing that could differ
  // from it.
  const evaluationContext = buildEvaluationContext({
    issuerContext,
    client: request.client,
    user: request.user,
    requested: request.requested,
    launchContext: request.launchContext,
    grantType: request.grantType,
  });

  const evaluated = evaluatePolicy(policy.document, evaluationContext);
  // The grant's ceiling and the policy's, resolved once and before anything is
  // assembled, so every consumer of the evaluation below - the claims, the
  // response, the stored expiry - sees the same lifetime.
  const ceiling = request.accessTokenTtlCeiling;
  const evaluation =
    ceiling === undefined
      ? evaluated
      : {
          ...evaluated,
          accessTokenTtl: Math.min(evaluated.accessTokenTtl, ceiling),
        };

  if (evaluation.grantedScopes.length === 0) {
    return { ok: false, reason: "nothing-granted" };
  }

  const load = await loadSigningKey(
    context.db,
    clientScope,
    context.config.masterKey,
  );
  if (!load.ok) {
    return { ok: false, reason: "no-signing-key" };
  }

  const now = context.clock();
  const issuedAt = Math.floor(now.getTime() / 1000);
  const jti = crypto.randomUUID();

  const issuance = {
    jti,
    issuedAt,
    subject: request.subject,
    ...(request.nonce === undefined ? {} : { nonce: request.nonce }),
    ...(request.authTime === undefined ? {} : { authTime: request.authTime }),
  };

  const accessClaims = assembleAccessTokenClaims({
    evaluation,
    context: evaluationContext,
    issuance,
  });
  const accessToken = await signClaims(accessClaims, load.signingKey);

  // An ID token is issued only when `openid` was granted *and* the endpoint is
  // configured for OpenID Connect. Both conditions, because a policy could grant
  // `openid` on an endpoint whose discovery document says it is not an OIDC
  // provider, and the document is the promise Signet has to keep.
  const wantsIdToken =
    issuerContext.endpoint.supportsOpenIdConnect &&
    hasIdentityScope(evaluation.grantedScopes, "openid") &&
    request.user !== null;

  const idTokenClaims = wantsIdToken
    ? assembleIdTokenClaims({
        evaluation,
        context: evaluationContext,
        issuance,
      })
    : undefined;
  const idToken =
    idTokenClaims === undefined
      ? undefined
      : await signClaims(idTokenClaims, load.signingKey);

  const grantedScopes = formatScopes(evaluation.grantedScopes);
  const expiresAt = new Date((issuedAt + evaluation.accessTokenTtl) * 1000);

  // A refresh token is never issued to a backend service: SMART Backend Services
  // forbids it, and a client that can mint its own assertion has no need of one.
  const wantsRefreshToken =
    request.grantType !== "client_credentials" &&
    grantsRefreshToken(evaluation.grantedScopes);
  const refreshToken = wantsRefreshToken ? generateOpaqueToken() : undefined;

  const replacement =
    refreshToken === undefined
      ? undefined
      : {
          tokenHash: await hashToken(refreshToken),
          subject: request.subject,
          scope: grantedScopes,
          launchContext: request.launchContext,
          expiresAt: new Date((issuedAt + evaluation.refreshTokenTtl) * 1000),
        };

  const rotate = request.rotate;
  if (rotate !== undefined) {
    // The presented token is spent whether or not a successor is issued. A policy
    // that stopped granting `offline_access` since the last refresh must end the
    // chain, not leave the old token live indefinitely.
    const rotation =
      replacement === undefined
        ? await withTenantScope(context.db, clientScope, (bound) =>
            redeemRefreshToken(bound, rotate.tokenHash, now),
          )
        : await withTenantScope(context.db, clientScope, (bound) =>
            redeemAndRotateRefreshToken(
              bound,
              rotate.tokenHash,
              {
                tokenHash: replacement.tokenHash,
                scope: replacement.scope,
                launchContext: replacement.launchContext,
                expiresAt: replacement.expiresAt,
              },
              now,
            ),
          );
    if (!rotation.ok) {
      return {
        ok: false,
        reason: "refresh-token-unusable",
        refresh: rotation.reason,
        familyRevoked: rotation.familyRevoked,
      };
    }
  } else if (replacement !== undefined) {
    await withTenantScope(context.db, clientScope, (bound) =>
      issueRefreshToken(bound, replacement),
    );
  }

  await withTenantScope(context.db, clientScope, (bound) =>
    recordAccessToken(bound, {
      jti,
      subject: request.subject,
      scope: grantedScopes,
      issuer: issuerContext.issuer,
      audience: issuerContext.endpoint.fhirBaseUrl,
      launchContext: request.launchContext,
      idTokenClaims: idTokenClaims ?? null,
      expiresAt,
    }),
  );

  return {
    ok: true,
    issued: {
      response: assembleTokenResponse({
        accessToken,
        expiresIn: evaluation.accessTokenTtl,
        scope: grantedScopes,
        ...(idToken === undefined ? {} : { idToken }),
        ...(refreshToken === undefined ? {} : { refreshToken }),
        contextParams: evaluation.contextParams,
      }),
      evaluation,
      policy,
      jti,
      grantedScopes,
    },
  };
}
