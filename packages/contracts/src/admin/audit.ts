/**
 * Audit browser query parameters.
 *
 * These arrive in a query string, so everything is coerced from a string and
 * nothing is required. The paging cursor is a single opaque parameter rather than
 * a timestamp and an identifier the caller assembles: it is the data layer's
 * keyset position, and a caller that could compose one by hand would be able to
 * ask for a page boundary that does not exist.
 *
 * A malformed filter is refused rather than ignored. An audit search that quietly
 * drops a constraint it did not understand tells the operator that nothing
 * matched, which is a different and much worse answer than "that filter is not
 * valid".
 *
 * Author: John Grimes
 */

import { z } from "zod";

/** Which end of the trail to read from. */
export const auditOrderSchema = z.enum(["newest-first", "oldest-first"]);

/** Kinds of principal an event may be attributed to. */
export const auditActorTypeSchema = z.enum([
  "admin-user",
  "api-token",
  "end-user",
  "client",
  "system",
]);

/** The audit browser's filter, as it appears in a query string. */
export const auditQuerySchema = z.object({
  endpointSlug: z.string().max(64).optional(),
  actorType: auditActorTypeSchema.optional(),
  actorId: z.string().max(256).optional(),
  /** Repeatable: `?action=authorize.denied&action=token.issued`. */
  action: z
    .union([z.string().max(128), z.array(z.string().max(128))])
    .optional(),
  targetType: z.string().max(64).optional(),
  targetId: z.string().max(256).optional(),
  from: z.coerce.date().optional(),
  until: z.coerce.date().optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
  /** The `nextCursor` from the previous page, verbatim. */
  cursor: z.string().max(512).optional(),
  order: auditOrderSchema.optional(),
});

export type AuditQuery = z.infer<typeof auditQuerySchema>;
