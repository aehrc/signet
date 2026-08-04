/**
 * Author: John Grimes
 */

import {
  PERMISSION_ORDER,
  type Permission,
  type Scope,
  type ScopeContext,
  type ScopeParameter,
  type ScopeParseErrorCode,
  type ScopeParseResult,
} from "./types.js";

const SCOPE_CONTEXTS = new Set<string>(["patient", "user", "system"]);
const IDENTITY_SCOPES = new Set<string>(["openid", "fhirUser", "profile"]);
const REFRESH_SCOPES = new Set<string>(["offline_access", "online_access"]);
const PERMISSION_LETTERS = new Set<string>(PERMISSION_ORDER);

/**
 * A FHIR resource type name: upper camel case, letters only.
 *
 * The spec permits `*` as a wildcard, handled separately.
 */
const RESOURCE_TYPE_PATTERN = /^[A-Z][A-Za-z]*$/;

/** Builds a failed parse result. */
function fail(code: ScopeParseErrorCode, message: string): ScopeParseResult {
  return { ok: false, code, message };
}

/**
 * Expands a SMART v1 permission suffix to its v2 equivalent.
 *
 * Returns `undefined` when the suffix is not a v1 form, so the caller can fall
 * through to v2 parsing.
 *
 * @see https://hl7.org/fhir/smart-app-launch/scopes-and-launch-context.html
 */
function expandV1Permissions(
  suffix: string,
): readonly Permission[] | undefined {
  switch (suffix) {
    case "read": {
      return ["r", "s"];
    }
    case "write": {
      return ["c", "u", "d"];
    }
    case "*": {
      return ["c", "r", "u", "d", "s"];
    }
    default: {
      return undefined;
    }
  }
}

/**
 * Parses a v2 permission suffix, enforcing that letters are known, unique and
 * in canonical `cruds` order.
 *
 * The spec allows servers to reject out-of-order suffixes, and Signet does:
 * silently reordering `.dus` into `.uds` would grant a permission set the
 * client did not write, which is the wrong default for an auth server.
 */
function parsePermissions(
  suffix: string,
):
  | { ok: true; permissions: readonly Permission[] }
  | { ok: false; result: ScopeParseResult } {
  if (suffix.length === 0) {
    return {
      ok: false,
      result: fail("missing-permissions", "Scope has an empty permission set"),
    };
  }

  const permissions: Permission[] = [];
  let previousIndex = -1;

  for (const letter of suffix) {
    if (!PERMISSION_LETTERS.has(letter)) {
      return {
        ok: false,
        result: fail(
          "unknown-permission",
          `Unknown permission letter "${letter}" in ".${suffix}"`,
        ),
      };
    }

    const permission = letter as Permission;
    const index = PERMISSION_ORDER.indexOf(permission);

    if (index === previousIndex) {
      return {
        ok: false,
        result: fail(
          "duplicate-permission",
          `Duplicate permission "${letter}" in ".${suffix}"`,
        ),
      };
    }
    if (index < previousIndex) {
      return {
        ok: false,
        result: fail(
          "unordered-permissions",
          `Permissions in ".${suffix}" are not in "cruds" order`,
        ),
      };
    }

    previousIndex = index;
    permissions.push(permission);
  }

  return { ok: true, permissions };
}

/**
 * Parses the search parameter restrictions that may follow `?` in a resource
 * scope, preserving written order and allowing a name to repeat.
 */
function parseParameters(
  query: string,
):
  | { ok: true; parameters: readonly ScopeParameter[] }
  | { ok: false; result: ScopeParseResult } {
  if (query.length === 0) {
    return {
      ok: false,
      result: fail(
        "malformed-parameters",
        "Scope ends with `?` but has no parameters",
      ),
    };
  }

  const parameters: ScopeParameter[] = [];

  for (const pair of query.split("&")) {
    const separator = pair.indexOf("=");
    if (separator <= 0 || separator === pair.length - 1) {
      return {
        ok: false,
        result: fail(
          "malformed-parameters",
          `Malformed scope parameter "${pair}"`,
        ),
      };
    }
    parameters.push({
      name: pair.slice(0, separator),
      value: decodeURIComponent(pair.slice(separator + 1)),
    });
  }

  return { ok: true, parameters };
}

/** Parses a `launch`, `launch/patient` or `launch/{type}?role=...` scope. */
function parseLaunchScope(raw: string): ScopeParseResult {
  if (raw === "launch") {
    return { ok: true, scope: { kind: "launch" } };
  }

  const remainder = raw.slice("launch/".length);
  if (remainder.length === 0) {
    return fail("malformed", "Scope `launch/` has no context type");
  }

  const [resource, query] = splitOnce(remainder, "?");
  if (resource.length === 0) {
    return fail("malformed", "Scope `launch/` has no context type");
  }

  if (query === undefined) {
    return { ok: true, scope: { kind: "launch", resource } };
  }

  const parsed = parseParameters(query);
  if (!parsed.ok) {
    return parsed.result;
  }

  const role = parsed.parameters.find(
    (parameter) => parameter.name === "role",
  )?.value;
  return {
    ok: true,
    scope:
      role === undefined
        ? { kind: "launch", resource }
        : { kind: "launch", resource, role },
  };
}

/** Splits on the first occurrence of a separator. */
function splitOnce(
  value: string,
  separator: string,
): [string, string | undefined] {
  const index = value.indexOf(separator);
  if (index === -1) {
    return [value, undefined];
  }
  return [value.slice(0, index), value.slice(index + separator.length)];
}

/** True when the scope is an opaque extension scope Signet passes through. */
function isCustomScope(raw: string): boolean {
  return (
    raw.startsWith("__") ||
    raw.startsWith("http://") ||
    raw.startsWith("https://")
  );
}

/**
 * Parses a single SMART scope string into a structured {@link Scope}.
 *
 * SMART v1 permission suffixes (`.read`, `.write`, `.*`) are normalised to
 * their v2 equivalents, so downstream code only ever sees `cruds` letters.
 *
 * @param raw - One scope string, with no surrounding whitespace.
 * @returns The parsed scope, or a failure describing why it was rejected.
 */
export function parseScope(raw: string): ScopeParseResult {
  if (raw.length === 0) {
    return fail("empty", "Scope is empty");
  }

  if (isCustomScope(raw)) {
    return { ok: true, scope: { kind: "custom", value: raw } };
  }

  if (IDENTITY_SCOPES.has(raw)) {
    return {
      ok: true,
      scope: {
        kind: "identity",
        name: raw as "openid" | "fhirUser" | "profile",
      },
    };
  }

  if (REFRESH_SCOPES.has(raw)) {
    return {
      ok: true,
      scope: {
        kind: "refresh",
        name: raw as "offline_access" | "online_access",
      },
    };
  }

  if (raw === "launch" || raw.startsWith("launch/")) {
    return parseLaunchScope(raw);
  }

  const slash = raw.indexOf("/");
  if (slash === -1) {
    return fail("malformed", `Scope "${raw}" is not a recognised SMART scope`);
  }

  const context = raw.slice(0, slash);
  if (!SCOPE_CONTEXTS.has(context)) {
    return fail("unknown-context", `Unknown scope context "${context}"`);
  }

  const [beforeQuery, query] = splitOnce(raw.slice(slash + 1), "?");
  const dot = beforeQuery.indexOf(".");
  if (dot === -1) {
    return fail(
      "missing-permissions",
      `Scope "${raw}" has no permission suffix`,
    );
  }

  const resourceType = beforeQuery.slice(0, dot);
  if (resourceType !== "*" && !RESOURCE_TYPE_PATTERN.test(resourceType)) {
    return fail(
      "invalid-resource-type",
      `Invalid resource type "${resourceType}" in "${raw}"`,
    );
  }

  const suffix = beforeQuery.slice(dot + 1);
  const permissions = expandV1Permissions(suffix);
  let resolved: readonly Permission[];

  if (permissions === undefined) {
    const parsed = parsePermissions(suffix);
    if (!parsed.ok) {
      return parsed.result;
    }
    resolved = parsed.permissions;
  } else {
    resolved = permissions;
  }

  let parameters: readonly ScopeParameter[] = [];
  if (query !== undefined) {
    const parsed = parseParameters(query);
    if (!parsed.ok) {
      return parsed.result;
    }
    parameters = parsed.parameters;
  }

  return {
    ok: true,
    scope: {
      kind: "resource",
      context: context as ScopeContext,
      resourceType,
      permissions: resolved,
      parameters,
    },
  };
}

/** The outcome of parsing a whole space-delimited scope string. */
export interface ParseScopesResult {
  /** Successfully parsed scopes, in requested order. */
  readonly scopes: readonly Scope[];
  /** Scope strings that could not be parsed, with the reason. */
  readonly rejected: readonly {
    readonly raw: string;
    readonly code: ScopeParseErrorCode;
    readonly message: string;
  }[];
}

/**
 * Parses a space-delimited scope string, as sent in an OAuth `scope` parameter.
 *
 * Unparseable entries are collected in `rejected` rather than throwing, because
 * the spec allows a server to ignore scopes it does not understand - but Signet
 * still needs to audit what it dropped.
 *
 * @param raw - The raw `scope` parameter value.
 */
export function parseScopes(raw: string): ParseScopesResult {
  const scopes: Scope[] = [];
  const rejected: {
    raw: string;
    code: ScopeParseErrorCode;
    message: string;
  }[] = [];

  for (const entry of raw.split(/\s+/).filter((value) => value.length > 0)) {
    const result = parseScope(entry);
    if (result.ok) {
      scopes.push(result.scope);
    } else {
      rejected.push({ raw: entry, code: result.code, message: result.message });
    }
  }

  return { scopes, rejected };
}
