/**
 * Launch context types.
 *
 * @see https://hl7.org/fhir/smart-app-launch/scopes-and-launch-context.html
 *
 * Author: John Grimes
 */

/** A FHIR Identifier, as permitted inside a `fhirContext` entry. */
export interface FhirIdentifier {
  readonly system?: string;
  readonly value?: string;
  readonly use?: string;
  readonly type?: unknown;
}

/**
 * One entry in the `fhirContext` array.
 *
 * Exactly one of `reference`, `canonical` or `identifier` must be present.
 */
export interface FhirContextEntry {
  /** A relative FHIR reference, e.g. `DiagnosticReport/123`. */
  readonly reference?: string;
  /** A canonical URL, optionally versioned with `|`. */
  readonly canonical?: string;
  readonly identifier?: FhirIdentifier;
  /** Recommended alongside `canonical` or `identifier`. */
  readonly type?: string;
  /** A URI describing the entry's role. Omission is equivalent to `launch`. */
  readonly role?: string;
}

/**
 * Resolved launch context for an authorization.
 *
 * `patient` and `encounter` stay top-level parameters rather than moving into
 * `fhirContext`; the spec forbids those types appearing there with the default
 * `launch` role.
 */
export interface LaunchContext {
  readonly patient?: string;
  readonly encounter?: string;
  readonly fhirContext?: readonly FhirContextEntry[];
  readonly intent?: string;
  readonly tenant?: string;
  readonly needPatientBanner?: boolean;
  readonly smartStyleUrl?: string;
}

/**
 * A launch context under construction, where a key may be present and undefined.
 *
 * The distinction matters because the codebase compiles with
 * `exactOptionalPropertyTypes`: `{ patient: undefined }` is not a
 * {@link LaunchContext}, and that is deliberate - a context whose `patient` key
 * exists but holds nothing would be serialised as `"patient": null` into a token
 * response, and SMART clients test for presence. A validated request body,
 * however, naturally has exactly that shape, so {@link toLaunchContext} is the
 * one place the two meet.
 */
export type LaunchContextDraft = {
  readonly [Key in keyof LaunchContext]?: LaunchContext[Key] | undefined;
};

/** Why a launch context was rejected. */
export type LaunchContextErrorCode =
  | "empty-fhir-context-entry"
  | "ambiguous-fhir-context-entry"
  | "forbidden-fhir-context-type"
  | "invalid-reference"
  | "invalid-canonical"
  | "invalid-identifier"
  | "invalid-patient-id"
  | "invalid-encounter-id"
  | "invalid-style-url";

/** A single problem found while validating a launch context. */
export interface LaunchContextIssue {
  readonly code: LaunchContextErrorCode;
  readonly message: string;
  /** Index into `fhirContext` when the issue concerns one entry. */
  readonly index?: number;
}

/** The outcome of validating a launch context. */
export type LaunchContextValidation =
  | { readonly ok: true; readonly context: LaunchContext }
  | { readonly ok: false; readonly issues: readonly LaunchContextIssue[] };
