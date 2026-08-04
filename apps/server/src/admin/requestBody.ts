/**
 * Reading and validating an admin API request body.
 *
 * Every mutating handler starts the same way - parse JSON, validate against a
 * contract, answer 400 with field-level issues if it does not hold - and doing
 * that inline in each would be thirty copies of the same four lines, one of which
 * would eventually forget the issues.
 *
 * A body that is not JSON at all is treated as an empty object rather than as a
 * parse error, so the response describes the fields that are missing instead of
 * complaining about syntax. That is the more useful answer: a client that sent
 * nothing and a client that sent `{}` have made the same mistake.
 *
 * Author: John Grimes
 */

import {
  adminErrorBody,
  issuesFromZodError,
  statusForAdminError,
} from "./errors.js";

import type { SignetEnvironment } from "../context.js";
import type { Context } from "hono";
import type { ZodType } from "zod";

/**
 * Parses and validates a JSON request body.
 *
 * @param c - The Hono request context.
 * @param schema - The contract the body must satisfy.
 * @returns The parsed value, or the `400` response to return instead. Callers
 *   branch on `instanceof Response`, which is the pattern the interaction API
 *   already uses for the same shape of decision.
 */
export async function parseBody<T>(
  c: Context<SignetEnvironment>,
  schema: ZodType<T>,
): Promise<T | Response> {
  const raw: unknown = await c.req.json().catch(() => ({}));
  const result = schema.safeParse(raw);
  if (!result.success) {
    return c.json(
      adminErrorBody(
        "invalid_request",
        "That request is not valid",
        issuesFromZodError(result.error),
      ),
      statusForAdminError("invalid_request"),
    );
  }
  return result.data;
}

/**
 * Validates a query string against a contract.
 *
 * Repeated parameters are collected into arrays, single ones left as strings, so a
 * schema can accept `?action=a&action=b` as well as `?action=a` - which is what the
 * audit browser's multi-select produces as its selection grows.
 *
 * @param c - The Hono request context.
 * @param schema - The contract the query must satisfy.
 */
export function parseQuery<T>(
  c: Context<SignetEnvironment>,
  schema: ZodType<T>,
): T | Response {
  const collected: Record<string, string | string[]> = {};
  for (const [name, values] of Object.entries(c.req.queries())) {
    if (values === undefined || values.length === 0) {
      continue;
    }
    collected[name] = values.length === 1 ? (values[0] as string) : values;
  }

  const result = schema.safeParse(collected);
  if (!result.success) {
    return c.json(
      adminErrorBody(
        "invalid_request",
        "That query is not valid",
        issuesFromZodError(result.error),
      ),
      statusForAdminError("invalid_request"),
    );
  }
  return result.data;
}

/**
 * The fields a patch actually named.
 *
 * A `PATCH` body carries only what is changing, and Zod fills the rest with
 * `undefined`. Passing that straight to a repository would blank every column the
 * caller did not mention, so the absent keys are dropped rather than written.
 *
 * The return type removes `undefined` from each value as well as making each key
 * optional, which is what `exactOptionalPropertyTypes` needs to see: "absent" and
 * "present and undefined" are different things, and only the first is what a patch
 * that omitted a field means.
 *
 * @param body - The parsed patch body.
 * @returns The same object with every `undefined` value removed.
 * @example
 * ```ts
 * const patch = definedFields(body);
 * const updated = await withTenantScope(context.db, scope, (bound) =>
 *   updateTenant(bound, patch, context.clock()),
 * );
 * ```
 */
export function definedFields<T extends object>(
  body: T,
): { [K in keyof T]?: Exclude<T[K], undefined> } {
  return Object.fromEntries(
    Object.entries(body).filter(([, value]) => value !== undefined),
  ) as { [K in keyof T]?: Exclude<T[K], undefined> };
}
