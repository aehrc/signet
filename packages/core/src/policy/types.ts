/**
 * Author: John Grimes
 */

import type { LaunchContext } from "../launch/types.js";
import type { Permission, Scope, ScopeContext } from "../scopes/types.js";

/** OAuth grant types Signet issues tokens for. */
export type GrantType =
  "authorization_code" | "client_credentials" | "refresh_token";

/** SMART client authentication postures. */
export type ClientType =
  "public" | "confidential-symmetric" | "confidential-asymmetric";

// A pattern matched against a scope, written as
// `{context|*}/{ResourceType|*}.{permissions}`, where either segment may be the
// wildcard `*`.
//
// Two different matching semantics are used, and each rule type below documents
// which one applies:
//
//   within (grant rules)
//     The scope's permissions must be a subset of the pattern's.
//     `patient/*.rs` permits `patient/Observation.r` but not
//     `patient/Observation.cud`. The right question for "may the client have
//     this?".
//
//   intersects (mapping rules)
//     The scope must share at least one permission with the pattern.
//     `*/*.r` matches `patient/Observation.rs` because both include `r`. The
//     right question for "does this scope imply a read authority?".
/** A scope pattern. See the commentary above for matching semantics. */
export type ScopePattern = string;

/** A parsed {@link ScopePattern}. */
export interface ParsedScopePattern {
  readonly context: ScopeContext | "*";
  readonly resourceType: string;
  readonly permissions: readonly Permission[];
}

/** Fields common to every rule, supporting the visual builder. */
export interface RuleMetadata {
  /** Stable identifier, so the UI can reorder rules without losing identity. */
  readonly id?: string;
  readonly description?: string;
  /** Absent means enabled. A disabled rule is retained but skipped. */
  readonly enabled?: boolean;
}

/**
 * Decides whether a requested scope is granted.
 *
 * Rules are evaluated in order and the first whose pattern matches decides the
 * outcome. A scope matching no rule is denied: an authorization server must
 * default to refusing, not to granting.
 *
 * Uses **within** matching.
 */
export interface ScopeGrantRule extends RuleMetadata {
  readonly match: ScopePattern;
  readonly allow: boolean;
  /**
   * When a requested scope asks for more permissions than this rule permits,
   * grant the overlap instead of refusing outright.
   *
   * The spec explicitly allows a server to grant narrower scopes than were
   * requested, and real apps routinely ask for `patient/*.cruds` whatever they
   * actually need. Without narrowing, a read-only policy answers such a request
   * with no data access at all, which fails opaquely at the first API call
   * rather than degrading to read.
   *
   * Narrowing is only attempted when NO rule matched the scope. An explicit
   * `allow: false` rule always wins, so a deny can never be narrowed around.
   */
  readonly narrow?: boolean;
  /** Launch context keys that must be present, e.g. `["patient"]`. */
  readonly requireContext?: readonly ("patient" | "encounter")[];
  /** The authenticated user must hold one of these roles. */
  readonly requireUserRole?: readonly string[];
  /** Restricts the rule to particular grant types. */
  readonly grantTypes?: readonly GrantType[];
  /** Restricts the rule to particular client types. */
  readonly clientTypes?: readonly ClientType[];
}

/** A condition gating a claim or context rule. */
export interface RuleCondition {
  /** Matches unconditionally. */
  readonly always?: boolean;
  /** At least one granted scope must match this pattern (**within**). */
  readonly scope?: ScopePattern;
  /** All of these launch context keys must be present and non-empty. */
  readonly context?: readonly (keyof LaunchContext)[];
  readonly grantTypes?: readonly GrantType[];
  readonly clientTypes?: readonly ClientType[];
  /** The authenticated user must hold one of these roles. */
  readonly userRole?: readonly string[];
  /** Requires an authenticated user (true) or requires none (false). */
  readonly hasUser?: boolean;
}

/** A JSON value a template may produce. */
export type TemplateValue =
  | string
  | number
  | boolean
  | null
  | readonly TemplateValue[]
  | { readonly [key: string]: TemplateValue };

/**
 * Emits claims into the signed access token.
 *
 * Every matching rule contributes. Later rules overwrite earlier ones for the
 * same claim name, so ordering is meaningful.
 */
export interface ClaimRule extends RuleMetadata {
  readonly when: RuleCondition;
  readonly emit: Readonly<Record<string, TemplateValue>>;
}

/** Emits parameters into the token response body rather than the token. */
export interface ContextRule extends RuleMetadata {
  readonly when?: RuleCondition;
  readonly emit: Readonly<Record<string, TemplateValue>>;
}

/**
 * Derives claim values from each granted scope individually, accumulating into
 * an array claim.
 *
 * This is what lets a policy translate SMART scopes into a resource server's own
 * vocabulary - Pathling's `authorities` claim, for instance, needs one entry per
 * resource type plus separate operation authorities.
 *
 * Uses **intersects** matching. Values are deduplicated, and order follows the
 * granted scopes.
 */
export interface ScopeMappingRule extends RuleMetadata {
  readonly when?: RuleCondition;
  /** Matched against each granted scope. */
  readonly forEachScope: ScopePattern;
  /** Claim name to append into. Created as an array if absent. */
  readonly appendTo: string;
  /** Templates evaluated with `scope` bound to the matching scope. */
  readonly values: readonly string[];
}

/** Token lifetimes and defaults. */
export interface PolicyDefaults {
  /** Access token lifetime in seconds. */
  readonly accessTokenTtl: number;
  /** Refresh token lifetime in seconds. */
  readonly refreshTokenTtl: number;
}

/** A complete, versioned policy document. */
export interface PolicyDocument {
  readonly version: 1;
  readonly scopeGrants: readonly ScopeGrantRule[];
  readonly claimRules: readonly ClaimRule[];
  readonly scopeMappings?: readonly ScopeMappingRule[];
  readonly contextRules: readonly ContextRule[];
  readonly defaults: PolicyDefaults;
}

/** The authenticated end user, absent for a `client_credentials` grant. */
export interface EvaluationUser {
  readonly id: string;
  /** Relative FHIR reference, e.g. `Practitioner/123`. */
  readonly fhirUser: string | null;
  readonly displayName: string | null;
  readonly roles: readonly string[];
  readonly attributes: Readonly<Record<string, unknown>>;
}

/** The endpoint an authorization is taking place on. */
export interface EvaluationEndpoint {
  readonly tenantSlug: string;
  readonly slug: string;
  /** Full issuer URL, e.g. `https://signet.example.org/t/demo/e/pathling`. */
  readonly issuer: string;
  /** The BYO FHIR server's base URL; the expected token `aud`. */
  readonly fhirBaseUrl: string;
}

/** The client requesting authorization. */
export interface EvaluationClient {
  readonly clientId: string;
  readonly name: string;
  readonly type: ClientType;
  readonly attributes: Readonly<Record<string, unknown>>;
}

/** Everything a policy may consider. Contains no I/O and no secrets. */
export interface EvaluationContext {
  readonly endpoint: EvaluationEndpoint;
  readonly client: EvaluationClient;
  readonly user: EvaluationUser | null;
  /** Requested scopes, already parsed and normalised to v2. */
  readonly requested: readonly Scope[];
  readonly context: LaunchContext;
  readonly grantType: GrantType;
}

/** A scope that was refused, and why. */
export interface DeniedScope {
  readonly scope: Scope;
  readonly reason: string;
  /** The `id` of the rule that denied it, when one matched. */
  readonly ruleId?: string;
}

/** A scope that was granted, but with fewer permissions than were requested. */
export interface NarrowedScope {
  readonly requested: Scope;
  readonly granted: Scope;
  /** The `id` of the rule that narrowed it, when it had one. */
  readonly ruleId?: string;
}

/** The result of evaluating a policy. */
export interface PolicyEvaluation {
  readonly grantedScopes: readonly Scope[];
  readonly deniedScopes: readonly DeniedScope[];
  /**
   * Scopes granted in reduced form. The reduced scope appears in
   * `grantedScopes`; this records what was asked for, so the decision is
   * auditable and the consent screen can be honest about it.
   */
  readonly narrowedScopes: readonly NarrowedScope[];
  /** Claims to merge into the signed access token. */
  readonly claims: Readonly<Record<string, unknown>>;
  /** Parameters to merge into the token response body. */
  readonly contextParams: Readonly<Record<string, unknown>>;
  readonly accessTokenTtl: number;
  readonly refreshTokenTtl: number;
}

/** A problem found while validating a policy document. */
export interface PolicyIssue {
  /** JSON path to the offending node, e.g. `claimRules[2].emit.patient_id`. */
  readonly path: string;
  readonly message: string;
}

/** The outcome of validating a policy document. */
export type PolicyValidation =
  | { readonly ok: true; readonly policy: PolicyDocument }
  | { readonly ok: false; readonly issues: readonly PolicyIssue[] };
