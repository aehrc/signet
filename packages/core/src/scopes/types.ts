/**
 * Types for the SMART App Launch 2.2.0 scope grammar.
 *
 * @see https://hl7.org/fhir/smart-app-launch/scopes-and-launch-context.html
 *
 * Author: John Grimes
 */

/** The three access contexts a resource scope can be requested in. */
export type ScopeContext = "patient" | "user" | "system";

/**
 * A single CRUDS permission letter.
 *
 * The spec defines these as an ordered set: a permission suffix must be a
 * subset of the in-order string `cruds`.
 */
export type Permission = "c" | "r" | "u" | "d" | "s";

/** Canonical ordering of permission letters. A suffix must respect this order. */
export const PERMISSION_ORDER: readonly Permission[] = [
  "c",
  "r",
  "u",
  "d",
  "s",
];

/** A search parameter restriction appended to a resource scope with `?`. */
export interface ScopeParameter {
  readonly name: string;
  readonly value: string;
}

/**
 * A resource access scope, e.g. `patient/Observation.rs?category=laboratory`.
 */
export interface ResourceScope {
  readonly kind: "resource";
  readonly context: ScopeContext;
  /** A FHIR resource type name, or `*` for the wildcard. */
  readonly resourceType: string;
  /** Permissions in canonical `cruds` order, deduplicated. */
  readonly permissions: readonly Permission[];
  /** Search parameter restrictions, in the order they were written. */
  readonly parameters: readonly ScopeParameter[];
}

/**
 * A launch context scope: bare `launch`, or `launch/patient`,
 * `launch/encounter`, `launch/{type}` with an optional `role` parameter.
 */
export interface LaunchScope {
  readonly kind: "launch";
  /** Absent for the bare `launch` scope used in an EHR launch. */
  readonly resource?: string;
  /** From `launch/list?role=...`; only meaningful when `resource` is present. */
  readonly role?: string;
}

/** An OpenID Connect identity scope. */
export interface IdentityScope {
  readonly kind: "identity";
  readonly name: "openid" | "fhirUser" | "profile";
}

/** A scope requesting a refresh token. */
export interface RefreshScope {
  readonly kind: "refresh";
  readonly name: "offline_access" | "online_access";
}

/**
 * A scope Signet does not interpret: a full URI (`https://example.org/foo`) or
 * a double-underscore experimental scope (`__profilePhoto.manage`).
 *
 * These are carried through so a policy can still match and act on them.
 */
export interface CustomScope {
  readonly kind: "custom";
  readonly value: string;
}

/** Any scope Signet can represent. */
export type Scope =
  ResourceScope | LaunchScope | IdentityScope | RefreshScope | CustomScope;

/** Why a scope string could not be parsed. */
export type ScopeParseErrorCode =
  | "empty"
  | "malformed"
  | "unknown-context"
  | "missing-permissions"
  | "unknown-permission"
  | "unordered-permissions"
  | "duplicate-permission"
  | "invalid-resource-type"
  | "malformed-parameters";

/** The outcome of parsing a single scope string. */
export type ScopeParseResult =
  | { readonly ok: true; readonly scope: Scope }
  | {
      readonly ok: false;
      readonly code: ScopeParseErrorCode;
      readonly message: string;
    };
