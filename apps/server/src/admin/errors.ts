/**
 * Admin API error responses.
 *
 * Deliberately not OAuth errors. The OAuth endpoints answer with the closed set of
 * codes RFC 6749 defines, because client libraries switch on them; the admin API
 * is consumed by the console and by scripts, and what those need is a stable code
 * plus a message an operator can act on. Mixing the two vocabularies would mean
 * `invalid_grant` appearing in a response to a form submission.
 *
 * Two invariants hold across every code here. A refusal never says whether the
 * thing asked for exists - an unknown tenant and a tenant the caller is not a
 * member of are both `not_found`, or the API would enumerate tenants for anyone
 * with an account. And no message ever quotes a credential back.
 *
 * Author: John Grimes
 */

import type { ZodError } from "zod";

/** The codes the admin API returns. */
export type AdminErrorCode =
  | "invalid_request"
  | "unauthenticated"
  | "forbidden"
  | "not_found"
  | "conflict";

/** One field-level problem, addressed by path. */
export interface AdminErrorIssue {
  /** Dotted path to the offending field, e.g. `redirectUris.0`. */
  readonly path: string;
  readonly message: string;
}

/** A serialised admin API error. */
export interface AdminErrorBody {
  readonly error: AdminErrorCode;
  readonly message: string;
  /** Present when the request was well-formed JSON but failed validation. */
  readonly issues?: readonly AdminErrorIssue[];
}

/**
 * The HTTP status for an admin error code.
 *
 * Kept as a total function over the union so that adding a code without deciding
 * its status is a compile error rather than a 500.
 */
export function statusForAdminError(
  code: AdminErrorCode,
): 400 | 401 | 403 | 404 | 409 {
  switch (code) {
    case "invalid_request": {
      return 400;
    }
    case "unauthenticated": {
      return 401;
    }
    case "forbidden": {
      return 403;
    }
    case "not_found": {
      return 404;
    }
    case "conflict": {
      return 409;
    }
  }
}

/**
 * Builds an error body, omitting `issues` rather than emitting an empty array.
 *
 * @param code - The admin API error code.
 * @param message - Operator-facing detail. Never a credential.
 * @param issues - Field-level problems, when the request failed validation.
 */
export function adminErrorBody(
  code: AdminErrorCode,
  message: string,
  issues?: readonly AdminErrorIssue[],
): AdminErrorBody {
  return {
    error: code,
    message,
    ...(issues === undefined || issues.length === 0 ? {} : { issues }),
  };
}

/**
 * Flattens a Zod error into field-level issues.
 *
 * The path is joined with dots, array indices included, so that
 * `redirectUris.0` addresses the same field the console rendered. Zod's own
 * nested shape is not reproduced: a form needs "which input, and what is wrong
 * with it", and reconstructing that from a tree is work every client would repeat.
 *
 * @param error - The failure from `safeParse`.
 */
export function issuesFromZodError(
  error: ZodError,
): readonly AdminErrorIssue[] {
  return error.issues.map((issue) => ({
    path: issue.path.map(String).join("."),
    message: issue.message,
  }));
}
