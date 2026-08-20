/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import type {
  FhirContextEntry,
  FhirIdentifier,
  LaunchContext,
  LaunchContextDraft,
  LaunchContextErrorCode,
  LaunchContextIssue,
  LaunchContextValidation,
} from "./types.js";

/**
 * Drops the keys that are present but hold nothing.
 *
 * A validated request body has `{ patient: undefined }` where the caller sent no
 * patient, which is not a {@link LaunchContext}: an absent value and a present
 * empty one are different signals to a SMART client, and the token response must
 * omit the parameter rather than serialise it as null. This is the one place that
 * conversion happens, so the cast it requires exists once.
 *
 * @param draft - A context whose optional keys may be explicitly undefined.
 */
export function toLaunchContext(draft: LaunchContextDraft): LaunchContext {
  return Object.fromEntries(
    Object.entries(draft).filter(([, value]) => value !== undefined),
  );
}

/**
 * The FHIR `id` datatype, which constrains both the logical id half of a
 * relative reference and the top-level `patient` / `encounter` parameters.
 */
const FHIR_ID_PATTERN = /^[A-Za-z0-9.-]{1,64}$/;

/** A FHIR resource type name: upper camel case, letters only. */
const RESOURCE_TYPE_PATTERN = /^[A-Z][A-Za-z]*$/;

/** A URI scheme, per RFC 3986. Presence of one is what makes a URL absolute. */
const URI_SCHEME_PATTERN = /^[A-Za-z][A-Za-z0-9+.-]*$/;

/**
 * Punctuation the RFC 3986 grammar excludes from a URI.
 *
 * Controls, space and delete are checked by code point alongside this set. URLs
 * are validated with a denylist rather than an allowlist so that
 * internationalised URLs still pass: the aim is to reject values that plainly
 * are not URLs, not to stand in for FHIR-level validation.
 */
const URI_EXCLUDED_CHARACTERS = new Set<string>([
  "<",
  ">",
  '"',
  "{",
  "}",
  "|",
  "\\",
  "^",
  "`",
]);

/** Schemes whose grammar requires an authority component. */
const AUTHORITY_SCHEMES = new Set<string>(["http", "https"]);

/**
 * Resource types that must travel as top-level parameters.
 *
 * These are the two types the spec explicitly refuses to deprecate from the top
 * level, so an app is entitled to find them there and nowhere else.
 */
const TOP_LEVEL_ONLY_TYPES = new Set<string>(["Patient", "Encounter"]);

/** The default `fhirContext` role, applied when `role` is omitted. */
const LAUNCH_ROLE = "launch";

/** Builds an issue that concerns the launch context as a whole. */
function issue(
  code: LaunchContextErrorCode,
  message: string,
): LaunchContextIssue {
  return { code, message };
}

/** Builds an issue that concerns one `fhirContext` entry. */
function entryIssue(
  code: LaunchContextErrorCode,
  message: string,
  index: number,
): LaunchContextIssue {
  return { code, message, index };
}

/** True when the value contains a character no URI may carry unencoded. */
function hasExcludedCharacters(value: string): boolean {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    // Everything up to and including space (32), plus delete (127), is a
    // control or whitespace character: never valid unencoded, and usually a
    // copy-paste accident rather than an intent.
    if (code <= 32 || code === 127) {
      return true;
    }
    if (URI_EXCLUDED_CHARACTERS.has(character)) {
      return true;
    }
  }
  return false;
}

/** True when the remainder after `scheme:` opens with a non-empty authority. */
function hasAuthority(remainder: string): boolean {
  if (!remainder.startsWith("//")) {
    return false;
  }
  const authority = remainder.slice(2).split(/[/?#]/, 1)[0] ?? "";
  return authority.length > 0;
}

/** The lower-cased scheme of an absolute URI, or `undefined` when there is none. */
function uriScheme(value: string): string | undefined {
  const colon = value.indexOf(":");
  if (colon === -1) {
    return undefined;
  }
  const scheme = value.slice(0, colon);
  return URI_SCHEME_PATTERN.test(scheme) ? scheme.toLowerCase() : undefined;
}

/**
 * True when the value is an absolute URI.
 *
 * Validation is structural: a scheme, a non-empty remainder, no excluded
 * characters, and an authority when the scheme demands one. This deliberately
 * accepts non-http schemes such as `urn:`, since a canonical URL may be a URN.
 */
function isAbsoluteUrl(value: string): boolean {
  const scheme = uriScheme(value);
  if (scheme === undefined || hasExcludedCharacters(value)) {
    return false;
  }
  const remainder = value.slice(scheme.length + 1);
  if (remainder.length === 0) {
    return false;
  }
  return !AUTHORITY_SCHEMES.has(scheme) || hasAuthority(remainder);
}

/** True when the value is an absolute URL whose scheme is `http` or `https`. */
function isAbsoluteHttpUrl(value: string): boolean {
  const scheme = uriScheme(value);
  return (
    scheme !== undefined &&
    AUTHORITY_SCHEMES.has(scheme) &&
    isAbsoluteUrl(value)
  );
}

/**
 * Extracts the resource type from a relative reference.
 *
 * Returns `undefined` when the prefix does not look like a resource type, so
 * callers never mistake a malformed reference for a typed one.
 */
function referenceType(reference: string): string | undefined {
  const slash = reference.indexOf("/");
  if (slash <= 0) {
    return undefined;
  }
  const type = reference.slice(0, slash);
  return RESOURCE_TYPE_PATTERN.test(type) ? type : undefined;
}

/** True when the value is a relative `Type/id` reference. */
function isValidReference(reference: string): boolean {
  const slash = reference.indexOf("/");
  if (slash === -1) {
    return false;
  }
  return (
    referenceType(reference) !== undefined &&
    FHIR_ID_PATTERN.test(reference.slice(slash + 1))
  );
}

/**
 * True when the value is a canonical URL, optionally suffixed with `|version`.
 *
 * A trailing `|` with no version, or more than one `|`, is rejected: both are
 * ambiguous about which version was meant.
 */
function isValidCanonical(canonical: string): boolean {
  const bar = canonical.indexOf("|");
  if (bar === -1) {
    return isAbsoluteUrl(canonical);
  }
  const version = canonical.slice(bar + 1);
  if (version.length === 0 || version.includes("|")) {
    return false;
  }
  return isAbsoluteUrl(canonical.slice(0, bar));
}

/**
 * True when an identifier carries enough to be worth conveying.
 *
 * Empty strings count as absent - `{ "value": "" }` identifies nothing, and
 * accepting it would push a meaningless context onto the app.
 */
function isValidIdentifier(identifier: FhirIdentifier): boolean {
  return (
    (identifier.system !== undefined && identifier.system.length > 0) ||
    (identifier.value !== undefined && identifier.value.length > 0)
  );
}

/**
 * True when the entry carries the default `launch` role.
 *
 * An omitted role is semantically `launch`. The spec also forbids the empty
 * string, and treating it as `launch` is the conservative reading: it must not
 * become a way to smuggle a Patient into `fhirContext`.
 */
function hasLaunchRole(entry: FhirContextEntry): boolean {
  return (
    entry.role === undefined ||
    entry.role.length === 0 ||
    entry.role === LAUNCH_ROLE
  );
}

/**
 * Best-effort resource type of a `fhirContext` entry.
 *
 * An explicit `type` wins, because it is the entry's own declaration; otherwise
 * the type is inferred from the reference prefix. Returns `undefined` when
 * neither source yields a plausible resource type, which is the normal case for
 * a `canonical` or `identifier` entry with no `type`.
 *
 * @param entry - The entry to inspect.
 * @returns The resource type, or `undefined` when it cannot be determined.
 */
export function fhirContextEntryType(
  entry: FhirContextEntry,
): string | undefined {
  if (entry.type !== undefined && entry.type.length > 0) {
    return entry.type;
  }
  return entry.reference === undefined
    ? undefined
    : referenceType(entry.reference);
}

/**
 * Every resource type the entry could be claiming to be.
 *
 * Both the declared `type` and the reference prefix are considered, so a
 * mislabelled entry such as `{ reference: "Patient/1", type: "Observation" }`
 * is still caught by the top-level-only check.
 */
function candidateTypes(entry: FhirContextEntry): readonly string[] {
  const types: string[] = [];
  if (entry.type !== undefined && entry.type.length > 0) {
    types.push(entry.type);
  }
  if (entry.reference !== undefined) {
    const inferred = referenceType(entry.reference);
    if (inferred !== undefined) {
      types.push(inferred);
    }
  }
  return types;
}

/** Collects the issues for a single `fhirContext` entry. */
function validateEntry(
  entry: FhirContextEntry,
  index: number,
): readonly LaunchContextIssue[] {
  const issues: LaunchContextIssue[] = [];
  const forms = [entry.reference, entry.canonical, entry.identifier].filter(
    (form) => form !== undefined,
  );

  if (forms.length === 0) {
    issues.push(
      entryIssue(
        "empty-fhir-context-entry",
        "fhirContext entry has none of `reference`, `canonical` or `identifier`",
        index,
      ),
    );
  } else if (forms.length > 1) {
    issues.push(
      entryIssue(
        "ambiguous-fhir-context-entry",
        "fhirContext entry has more than one of `reference`, `canonical` or `identifier`",
        index,
      ),
    );
  }

  if (entry.reference !== undefined && !isValidReference(entry.reference)) {
    issues.push(
      entryIssue(
        "invalid-reference",
        `fhirContext reference "${entry.reference}" is not a relative Type/id reference`,
        index,
      ),
    );
  }

  if (entry.canonical !== undefined && !isValidCanonical(entry.canonical)) {
    issues.push(
      entryIssue(
        "invalid-canonical",
        `fhirContext canonical "${entry.canonical}" is not an absolute URL with an optional |version suffix`,
        index,
      ),
    );
  }

  if (entry.identifier !== undefined && !isValidIdentifier(entry.identifier)) {
    issues.push(
      entryIssue(
        "invalid-identifier",
        "fhirContext identifier has neither `system` nor `value`",
        index,
      ),
    );
  }

  if (hasLaunchRole(entry)) {
    for (const type of candidateTypes(entry)) {
      if (TOP_LEVEL_ONLY_TYPES.has(type)) {
        issues.push(
          entryIssue(
            "forbidden-fhir-context-type",
            `${type} must be conveyed as a top-level launch parameter, not in fhirContext with the default "launch" role`,
            index,
          ),
        );
      }
    }
  }

  return issues;
}

/**
 * Validates a resolved launch context against the SMART App Launch rules.
 *
 * All issues are collected rather than short-circuiting on the first, so an
 * operator debugging a policy sees everything wrong with a context at once.
 * The check is purely structural: it says nothing about whether the referenced
 * resources exist, or whether the requester is allowed to see them.
 *
 * @param context - The launch context to validate.
 * @returns The context itself when valid, otherwise the issues found.
 * @see https://hl7.org/fhir/smart-app-launch/scopes-and-launch-context.html
 */
export function validateLaunchContext(
  context: LaunchContext,
): LaunchContextValidation {
  const issues: LaunchContextIssue[] = [];

  if (context.patient !== undefined && !FHIR_ID_PATTERN.test(context.patient)) {
    issues.push(
      issue(
        "invalid-patient-id",
        `Patient id "${context.patient}" is not a valid FHIR id`,
      ),
    );
  }

  if (
    context.encounter !== undefined &&
    !FHIR_ID_PATTERN.test(context.encounter)
  ) {
    issues.push(
      issue(
        "invalid-encounter-id",
        `Encounter id "${context.encounter}" is not a valid FHIR id`,
      ),
    );
  }

  if (
    context.smartStyleUrl !== undefined &&
    !isAbsoluteHttpUrl(context.smartStyleUrl)
  ) {
    issues.push(
      issue(
        "invalid-style-url",
        `smartStyleUrl "${context.smartStyleUrl}" is not an absolute http(s) URL`,
      ),
    );
  }

  if (context.fhirContext !== undefined) {
    for (const [index, entry] of context.fhirContext.entries()) {
      issues.push(...validateEntry(entry, index));
    }
  }

  return issues.length === 0 ? { ok: true, context } : { ok: false, issues };
}

/** Serialises an identifier, dropping absent properties. */
function toWireIdentifier(identifier: FhirIdentifier): Record<string, unknown> {
  const wire: Record<string, unknown> = {};
  if (identifier.system !== undefined) {
    wire.system = identifier.system;
  }
  if (identifier.value !== undefined) {
    wire.value = identifier.value;
  }
  if (identifier.use !== undefined) {
    wire.use = identifier.use;
  }
  if (identifier.type !== undefined) {
    wire.type = identifier.type;
  }
  return wire;
}

/**
 * Serialises one `fhirContext` entry to its wire shape.
 *
 * Absent properties are dropped entirely: SMART clients test for presence, and
 * an explicit `null` is not the same signal as omission.
 */
function toWireFhirContextEntry(
  entry: FhirContextEntry,
): Record<string, unknown> {
  const wire: Record<string, unknown> = {};
  if (entry.reference !== undefined) {
    wire.reference = entry.reference;
  }
  if (entry.canonical !== undefined) {
    wire.canonical = entry.canonical;
  }
  if (entry.identifier !== undefined) {
    wire.identifier = toWireIdentifier(entry.identifier);
  }
  if (entry.type !== undefined) {
    wire.type = entry.type;
  }
  if (entry.role !== undefined) {
    wire.role = entry.role;
  }
  return wire;
}

/**
 * Renders a launch context into the parameter names used in a token response.
 *
 * The wire names are snake case for the SMART-specific flags but camel case for
 * `fhirContext`; that inconsistency belongs to the specification, not here.
 * Absent values are omitted rather than emitted as `null`, and an empty
 * `fhirContext` array is treated as absent because it conveys nothing.
 *
 * @param context - The launch context to render.
 * @returns Token response parameters, ready to merge into the response body.
 * @see https://hl7.org/fhir/smart-app-launch/scopes-and-launch-context.html
 */
export function toTokenResponseContext(
  context: LaunchContext,
): Record<string, unknown> {
  const parameters: Record<string, unknown> = {};

  if (context.patient !== undefined) {
    parameters.patient = context.patient;
  }
  if (context.encounter !== undefined) {
    parameters.encounter = context.encounter;
  }
  if (context.fhirContext !== undefined && context.fhirContext.length > 0) {
    parameters.fhirContext = context.fhirContext.map(toWireFhirContextEntry);
  }
  if (context.intent !== undefined) {
    parameters.intent = context.intent;
  }
  if (context.tenant !== undefined) {
    parameters.tenant = context.tenant;
  }
  if (context.needPatientBanner !== undefined) {
    parameters.need_patient_banner = context.needPatientBanner;
  }
  if (context.smartStyleUrl !== undefined) {
    parameters.smart_style_url = context.smartStyleUrl;
  }

  return parameters;
}
