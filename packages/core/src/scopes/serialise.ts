import type { Scope, ScopeParameter } from "./types.js";

/** Renders search parameter restrictions back into a query string. */
function formatParameters(parameters: readonly ScopeParameter[]): string {
  if (parameters.length === 0) {
    return "";
  }
  const pairs = parameters.map(
    (parameter) => `${parameter.name}=${encodeURIComponent(parameter.value)}`,
  );
  return `?${pairs.join("&")}`;
}

/**
 * Renders a {@link Scope} back to its canonical SMART v2 string form.
 *
 * Round-tripping a v1 scope through {@link parseScope} and this function
 * returns the v2 equivalent — `patient/Observation.read` becomes
 * `patient/Observation.rs` — which is what should be reported in the token
 * response `scope` value so the client sees what it actually got.
 *
 * @param scope - The scope to render.
 */
export function formatScope(scope: Scope): string {
  switch (scope.kind) {
    case "resource": {
      const permissions = scope.permissions.join("");
      return `${scope.context}/${scope.resourceType}.${permissions}${formatParameters(scope.parameters)}`;
    }
    case "launch": {
      if (scope.resource === undefined) {
        return "launch";
      }
      return scope.role === undefined
        ? `launch/${scope.resource}`
        : `launch/${scope.resource}?role=${encodeURIComponent(scope.role)}`;
    }
    case "identity": {
      return scope.name;
    }
    case "refresh": {
      return scope.name;
    }
    case "custom": {
      return scope.value;
    }
  }
}

/**
 * Renders a list of scopes into a space-delimited OAuth `scope` value.
 *
 * @param scopes - The scopes to render, in the order they should appear.
 */
export function formatScopes(scopes: readonly Scope[]): string {
  return scopes.map(formatScope).join(" ");
}
