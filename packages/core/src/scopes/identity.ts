/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import type { IdentityScope, Scope } from "./types.js";

/**
 * True when the granted scopes include the named identity scope.
 *
 * @param granted - The scopes actually granted, never the ones requested.
 * @param name - The identity scope to look for.
 */
export function hasIdentityScope(
  granted: readonly Scope[],
  name: IdentityScope["name"],
): boolean {
  return granted.some(
    (scope) => scope.kind === "identity" && scope.name === name,
  );
}
