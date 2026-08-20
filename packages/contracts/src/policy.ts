/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The policy document, as a Zod schema.
 *
 * The validation itself is not reimplemented here. `@signet/core` already owns it
 * - `validatePolicy` knows the scope-pattern grammar, the closed set of template
 * filters and which rule fields may appear together - and a second description of
 * the same document in Zod would be a second thing to keep in step, with the
 * failure mode that the API accepts a policy the evaluator then refuses.
 *
 * So this is an adapter: it runs the core validator and translates its issues
 * into Zod's, which is what lets a policy document sit inside a larger request
 * schema and produce one coherent error response.
 *
 * Author: John Grimes
 */

import { validatePolicy } from "@signet/core";
import { z } from "zod";

/**
 * Splits a core policy issue path into Zod path segments.
 *
 * Core reports paths in JavaScript accessor form - `claimRules[2].emit.patient_id`
 * - because that is what an operator sees in the code editor. Zod wants
 * `["claimRules", 2, "emit", "patient_id"]`, with array indices as numbers, so the
 * console can attach the message to the field the builder rendered.
 *
 * A segment that is neither a property name nor an index is passed through as a
 * string rather than dropped: an unexpected path shape should misplace a message,
 * not lose it.
 *
 * @param path - A path as `validatePolicy` reports it. May be empty, meaning the
 *   document as a whole.
 */
export function policyIssuePath(path: string): (string | number)[] {
  if (path === "") {
    return [];
  }

  const segments: (string | number)[] = [];
  for (const part of path.split(".")) {
    // A single part may carry indices, as in `values[0]` or even `a[0][1]`.
    const [name, ...indices] = part.split("[");
    if (name !== undefined && name !== "") {
      segments.push(name);
    }
    for (const index of indices) {
      const digits = index.replace("]", "");
      segments.push(/^\d+$/.test(digits) ? Number(digits) : digits);
    }
  }
  return segments;
}

/**
 * A complete policy document.
 *
 * Parses to the `PolicyDocument` the evaluator accepts, so a handler that has
 * parsed a request body needs no further narrowing before publishing it.
 */
export const policyDocumentSchema = z.unknown().transform((value, ctx) => {
  const validation = validatePolicy(value);
  if (!validation.ok) {
    for (const issue of validation.issues) {
      ctx.addIssue({
        code: "custom",
        message: issue.message,
        path: policyIssuePath(issue.path),
      });
    }
    return z.NEVER;
  }
  return validation.policy;
});
