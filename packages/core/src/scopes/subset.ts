/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import type { ResourceScope, Scope } from "./types.js";

/**
 * True when every restriction on `permitted` is also present on `candidate`.
 *
 * Restrictions only ever narrow access, so a candidate with *more* restrictions
 * than permitted is still within bounds. The reverse is not true: if the
 * permitted scope is limited to `category=laboratory`, a candidate without that
 * restriction is asking for more.
 */
function satisfiesParameters(
  candidate: ResourceScope,
  permitted: ResourceScope,
): boolean {
  return permitted.parameters.every((required) =>
    candidate.parameters.some(
      (present) =>
        present.name === required.name && present.value === required.value,
    ),
  );
}

/** True when `candidate` grants no more resource access than `permitted`. */
function isResourceSubset(
  candidate: ResourceScope,
  permitted: ResourceScope,
): boolean {
  if (candidate.context !== permitted.context) {
    return false;
  }
  if (
    permitted.resourceType !== "*" &&
    permitted.resourceType !== candidate.resourceType
  ) {
    return false;
  }
  const allowed = new Set(permitted.permissions);
  if (!candidate.permissions.every((permission) => allowed.has(permission))) {
    return false;
  }
  return satisfiesParameters(candidate, permitted);
}

/**
 * True when `candidate` grants no more access than `permitted`.
 *
 * This is the single comparison behind two checks that must never disagree:
 * narrowing scopes on a refresh grant, and holding a request inside a client's
 * configured allowlist.
 *
 * @param candidate - The scope being requested.
 * @param permitted - A scope the client is known to hold.
 */
export function isScopeSubsetOf(candidate: Scope, permitted: Scope): boolean {
  if (candidate.kind !== permitted.kind) {
    return false;
  }

  switch (candidate.kind) {
    case "resource": {
      return isResourceSubset(candidate, permitted as ResourceScope);
    }
    case "launch": {
      const other = permitted as Extract<Scope, { kind: "launch" }>;
      return (
        candidate.resource === other.resource && candidate.role === other.role
      );
    }
    case "identity": {
      return (
        candidate.name ===
        (permitted as Extract<Scope, { kind: "identity" }>).name
      );
    }
    case "refresh": {
      return (
        candidate.name ===
        (permitted as Extract<Scope, { kind: "refresh" }>).name
      );
    }
    case "custom": {
      return (
        candidate.value ===
        (permitted as Extract<Scope, { kind: "custom" }>).value
      );
    }
  }
}

/**
 * True when at least one scope in `permitted` covers `candidate`.
 *
 * @param candidate - The scope being requested.
 * @param permitted - The set of scopes the client holds.
 */
export function isScopeCoveredBy(
  candidate: Scope,
  permitted: readonly Scope[],
): boolean {
  return permitted.some((entry) => isScopeSubsetOf(candidate, entry));
}

/**
 * True when every scope in `candidates` is covered by `permitted`.
 *
 * @param candidates - The scopes being requested.
 * @param permitted - The set of scopes the client holds.
 */
export function areScopesCoveredBy(
  candidates: readonly Scope[],
  permitted: readonly Scope[],
): boolean {
  return candidates.every((candidate) =>
    isScopeCoveredBy(candidate, permitted),
  );
}

/**
 * Returns only those candidates covered by `permitted`, preserving order.
 *
 * Used when a server is permitted to narrow a request rather than reject it.
 *
 * @param candidates - The scopes being requested.
 * @param permitted - The set of scopes the client holds.
 */
export function narrowToPermitted(
  candidates: readonly Scope[],
  permitted: readonly Scope[],
): readonly Scope[] {
  return candidates.filter((candidate) =>
    isScopeCoveredBy(candidate, permitted),
  );
}
