import type { LaunchContext } from "../launch/types.js";
import type { EvaluationContext, PolicyEvaluation } from "../policy/types.js";

/** Registered JWT claims Signet always controls itself. */
export interface RegisteredClaims {
  readonly iss: string;
  readonly aud: string | readonly string[];
  readonly sub: string;
  readonly exp: number;
  readonly iat: number;
  readonly jti: string;
}

/**
 * A fully assembled access token payload.
 *
 * Policy-supplied claims are merged underneath the registered claims, so a
 * policy can never overwrite `iss`, `aud`, `exp`, `sub` or `jti` — those are
 * security-bearing and belong to the server, not to configuration.
 */
export type AccessTokenClaims = RegisteredClaims & {
  readonly scope: string;
  readonly client_id: string;
  readonly [claim: string]: unknown;
};

/** An assembled OpenID Connect ID token payload. */
export type IdTokenClaims = RegisteredClaims & {
  readonly azp?: string;
  readonly nonce?: string;
  readonly auth_time?: number;
  /** Relative FHIR reference to the resource representing the user. */
  readonly fhirUser?: string;
  readonly profile?: string;
  readonly [claim: string]: unknown;
};

/** Values the server supplies that a policy must not be able to influence. */
export interface TokenIssuanceParameters {
  /** Unique token identifier, used for introspection and revocation. */
  readonly jti: string;
  /** Issuance time as seconds since the epoch. */
  readonly issuedAt: number;
  /** Subject: the end user's id, or the client id for a backend service. */
  readonly subject: string;
  /** When present, added as a `nonce` claim on the ID token. */
  readonly nonce?: string;
  /** When the end user authenticated, as seconds since the epoch. */
  readonly authTime?: number;
}

/** The token response body returned from the token endpoint. */
export interface TokenResponse {
  readonly access_token: string;
  readonly token_type: "Bearer";
  readonly expires_in: number;
  readonly scope: string;
  readonly id_token?: string;
  readonly refresh_token?: string;
  readonly [parameter: string]: unknown;
}

/** Inputs for assembling a token response body. */
export interface TokenResponseInput {
  readonly accessToken: string;
  readonly expiresIn: number;
  readonly scope: string;
  readonly idToken?: string;
  readonly refreshToken?: string;
  /** Launch context parameters and anything else the policy emitted. */
  readonly contextParams: Readonly<Record<string, unknown>>;
}

/** Inputs for assembling access token claims. */
export interface AccessTokenInput {
  readonly evaluation: PolicyEvaluation;
  readonly context: EvaluationContext;
  readonly issuance: TokenIssuanceParameters;
}

/**
 * An RFC 7662 introspection response, with the SMART additions.
 *
 * Launch context present on the original token is echoed here, and ID token
 * claims are included when one was issued.
 */
export interface IntrospectionResponse {
  readonly active: boolean;
  readonly scope?: string;
  readonly client_id?: string;
  readonly exp?: number;
  readonly iat?: number;
  readonly sub?: string;
  readonly aud?: string | readonly string[];
  readonly iss?: string;
  readonly token_type?: "Bearer";
  readonly [parameter: string]: unknown;
}

/** A stored token record, as introspection sees it. */
export interface IntrospectableToken {
  readonly jti: string;
  readonly clientId: string;
  readonly subject: string;
  readonly scope: string;
  readonly issuer: string;
  readonly audience: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly revokedAt: number | null;
  readonly launchContext: LaunchContext;
  /** Claims from the ID token issued alongside, when there was one. */
  readonly idTokenClaims: Readonly<Record<string, unknown>> | null;
}
