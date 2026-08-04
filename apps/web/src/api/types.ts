/**
 * What the admin API returns, as the console reads it.
 *
 * Hand-written rather than inferred from a contract, and deliberately so: these are
 * response* shapes, and the contracts package describes *requests*. A response is
 * an explicit projection chosen by the server - see its `views.ts` - so a type
 * derived from a database row would claim fields the API does not send, including
 * ones it deliberately withholds.
 *
 * Timestamps arrive as ISO strings, because that is what JSON carries. They are
 * typed as strings rather than dates for the same reason: pretending otherwise
 * would put a `new Date()` somewhere other than the one formatting function that
 * should own it.
 *
 * Author: John Grimes
 */

/** The signed-in person, and the tenants they may act on. */
export interface SessionView {
  readonly user?: {
    readonly id: string;
    readonly email: string;
    readonly displayName: string;
    readonly totpEnrolled: boolean;
  };
  /** Present instead of `user` when a personal access token is being used. */
  readonly token?: {
    readonly id: string;
    readonly name: string;
    readonly role: string;
  };
  readonly tenants: readonly {
    readonly slug: string;
    readonly name?: string;
    readonly role: string;
  }[];
}

/** An endpoint's capability flags, keyed by the name the API uses. */
export type CapabilityFlags = Readonly<Record<string, boolean>>;

/** One endpoint. */
export interface EndpointView {
  readonly slug: string;
  readonly name: string;
  readonly description: string | null;
  readonly fhirBaseUrl: string;
  readonly issuer: string;
  readonly smartConfigurationUrl: string;
  readonly status: "active" | "disabled";
  readonly authMode: "local" | "persona" | "oidc";
  readonly consentMode: "always" | "remember" | "auto";
  readonly isProduction: boolean;
  readonly accessTokenTtl: number;
  readonly refreshTokenTtl: number;
  readonly scopesSupported: readonly string[];
  readonly userAccessBrandBundle: string | null;
  readonly userAccessBrandIdentifier: string | null;
  readonly capabilities: CapabilityFlags;
  readonly createdAt: string;
  readonly updatedAt: string;
}

/** One signing key. */
export interface EndpointKeyView {
  readonly kid: string;
  readonly algorithm: "RS384" | "ES384" | "RS256";
  readonly status: "active" | "next" | "retired";
  readonly publicJwk: Readonly<Record<string, unknown>>;
  readonly createdAt: string;
  readonly activatedAt: string | null;
  readonly retiredAt: string | null;
}

/** One registered client. */
export interface ClientView {
  readonly clientId: string;
  readonly name: string;
  readonly description: string | null;
  readonly logoUrl: string | null;
  readonly clientType:
    "public" | "confidential-symmetric" | "confidential-asymmetric";
  /** Presence only. The secret itself is shown once, at creation or rotation. */
  readonly hasSecret: boolean;
  readonly secretExpiresAt: string | null;
  readonly jwks: Readonly<Record<string, unknown>> | null;
  readonly jwksUri: string | null;
  readonly redirectUris: readonly string[];
  readonly launchUri: string | null;
  readonly grantTypes: readonly string[];
  readonly allowedScopes: readonly string[];
  readonly status: "pending" | "active" | "suspended" | "rejected";
  readonly contactEmail: string | null;
  readonly createdAt: string;
}

/** One end user or persona. */
export interface EndUserView {
  readonly id: string;
  readonly username: string;
  readonly displayName: string;
  readonly fhirUser: string | null;
  readonly roles: readonly string[];
  readonly attributes: Readonly<Record<string, unknown>>;
  readonly defaultContext: Readonly<Record<string, unknown>> | null;
  readonly isPersona: boolean;
  readonly hasPassword: boolean;
  readonly disabledAt: string | null;
  readonly createdAt: string;
}

/** One policy version. */
export interface PolicyView {
  readonly version: number;
  readonly document: unknown;
  readonly note: string | null;
  readonly published: boolean;
  readonly createdAt: string;
}

/** A developer's registration request. */
export interface ClientRequestView {
  readonly id: string;
  readonly requestedByEmail: string;
  readonly payload: {
    readonly name: string;
    readonly description?: string;
    readonly logoUrl?: string;
    readonly clientType: string;
    readonly redirectUris: readonly string[];
    readonly launchUri?: string;
    readonly requestedScopes: readonly string[];
    readonly contactEmail: string;
    readonly note?: string;
  };
  readonly status: "pending" | "approved" | "rejected";
  readonly decisionNote: string | null;
  readonly resultingClientId: string | null;
  readonly createdAt: string;
  readonly decidedAt: string | null;
}

/** One tenant membership. */
export interface MemberView {
  readonly adminUserId: string;
  readonly role: string;
  readonly email: string;
  readonly displayName: string;
  readonly lastLoginAt: string | null;
  readonly disabledAt: string | null;
  readonly totpEnrolled: boolean;
}

/** One personal access token. */
export interface ApiTokenView {
  readonly id: string;
  readonly name: string;
  readonly role: string;
  readonly createdAt: string;
  readonly expiresAt: string | null;
  readonly lastUsedAt: string | null;
  readonly revokedAt: string | null;
}

/** One audit event. */
export interface AuditEventView {
  readonly id: string;
  readonly at: string;
  readonly action: string;
  readonly description: string | null;
  readonly actorType: string;
  readonly actorId: string | null;
  readonly endpointId: string | null;
  readonly targetType: string | null;
  readonly targetId: string | null;
  readonly detail: Readonly<Record<string, unknown>>;
  readonly ip: string | null;
  readonly userAgent: string | null;
}

/** One page of the audit trail. */
export interface AuditPage {
  readonly events: readonly AuditEventView[];
  readonly nextCursor: string | null;
}

/** A policy starting point this deployment ships. */
export interface PresetView {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly policy: unknown;
  /**
   * Where the claim contract this preset asserts is documented.
   *
   * Shown beside the preset, because a preset says what another system will do with a
   * token and an operator cannot check that without the page it came from.
   */
  readonly references: readonly {
    readonly label: string;
    readonly url: string;
  }[];
}

/** The upstream identity provider an endpoint federates to. */
export interface IdpConfigView {
  readonly issuer: string;
  readonly displayName: string | null;
  readonly clientId: string;
  /**
   * Whether a secret is stored, never the secret itself.
   *
   * The API has no field that returns it, deliberately - the console shows that one
   * exists so an operator knows whether to re-enter it, and nothing more.
   */
  readonly hasClientSecret: boolean;
  readonly scopes: readonly string[];
  readonly claimMappings: {
    readonly fhirUser?: string;
    readonly roles?: string;
    readonly displayName?: string;
    readonly attributes?: readonly string[];
  };
  readonly discoveryCachedAt: string | null;
  readonly updatedAt: string;
  /** Where the provider must be told to redirect back to. */
  readonly redirectUri: string;
}

/** What a discovery check found. */
export type IdpCheckView =
  | {
      readonly ok: true;
      readonly supportsPkce: boolean;
      readonly metadata: {
        readonly issuer: string;
        readonly authorizationEndpoint: string;
        readonly tokenEndpoint: string;
        readonly jwksUri: string;
        readonly userinfoEndpoint?: string;
      };
    }
  | {
      readonly ok: false;
      readonly problem: string;
      readonly description: string;
    };

/** What a simulation reports. */
export interface SimulationView {
  readonly scope: string;
  readonly granted: readonly unknown[];
  readonly denied: readonly {
    readonly scope: unknown;
    readonly reason: string;
    readonly ruleId?: string;
  }[];
  readonly narrowed: readonly {
    readonly requested: unknown;
    readonly granted: unknown;
    readonly ruleId?: string;
  }[];
  readonly rejectedScopes: readonly {
    readonly raw: string;
    readonly message: string;
  }[];
  readonly accessTokenClaims: Readonly<Record<string, unknown>>;
  readonly idTokenClaims: Readonly<Record<string, unknown>> | null;
  readonly responseParameters: Readonly<Record<string, unknown>>;
  readonly accessTokenTtl: number;
  readonly refreshTokenTtl: number;
  readonly wouldIssueRefreshToken: boolean;
  readonly simulatedVersion: number | null;
}

/** What the launch simulator returns. */
export interface LaunchSimulationView {
  readonly launch: string;
  readonly iss: string;
  readonly expiresIn: number;
  readonly launchUrl: string | null;
}
