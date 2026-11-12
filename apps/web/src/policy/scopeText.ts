/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The text of a scope the policy simulator returned.
 *
 * The simulation API returns parsed scopes rather than strings, because the
 * evaluation works on parsed ones. Reassembling the text here rather than asking the
 * server for both keeps the response one representation, and doing it with core's
 * `formatScope` means the simulator writes a scope exactly as the token issuer does.
 *
 * Author: John Grimes
 */

import { formatScope } from "@signet/core";

import type { Scope } from "@signet/core";

/**
 * Every kind of parsed scope core knows how to write back out. A total record, so a
 * new kind of scope is a compile error here rather than a scope shown as JSON.
 */
const SCOPE_KINDS: Readonly<Record<Scope["kind"], true>> = {
  resource: true,
  launch: true,
  identity: true,
  refresh: true,
  custom: true,
};

/**
 * Renders a scope from a simulation response as its string form.
 *
 * @param scope - A parsed scope as the API returned it.
 * @returns The scope's canonical string; a string as it is; and anything else as
 * JSON, so an unrecognised shape is shown rather than hidden.
 * @example
 * scopeText({ kind: "custom", value: "orders:write" }); // "orders:write"
 */
export function scopeText(scope: unknown): string {
  if (typeof scope === "string") {
    return scope;
  }
  if (
    typeof scope === "object" &&
    scope !== null &&
    "kind" in scope &&
    typeof scope.kind === "string" &&
    Object.hasOwn(SCOPE_KINDS, scope.kind)
  ) {
    // The response is the evaluator's own output, so a recognised kind carries the
    // fields that kind is defined with.
    return formatScope(scope as Scope);
  }
  return JSON.stringify(scope);
}
