/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Counting ceremony challenges, for the suites that assert on their absence.
 *
 * A challenge that was *not* minted leaves nothing to read - there is no row, no
 * response field and no audit event - so the only way to assert that a refused
 * request wrote none is to count the table before and after. That is a question the
 * repositories have no reason to answer, and the server's suite cannot ask it
 * directly: only this package depends on Drizzle. So it lives here, beside the other
 * probes, for the same reason they do.
 *
 * Author: John Grimes
 */

import { sql } from "drizzle-orm";

import { adminPasskeyChallenges } from "../schema/tenancy.js";

import type { Executor } from "../repositories/executor.js";

/**
 * How many ceremony challenges are outstanding.
 *
 * Across the whole table rather than per account, which is what a before-and-after
 * comparison within one test needs and all it needs.
 *
 * @param db - The connection to count on.
 * @returns The number of rows in `admin_passkey_challenges`.
 */
export async function countAdminPasskeyChallenges(
  db: Executor,
): Promise<number> {
  const rows = await db
    .select({ total: sql<number>`count(*)::int` })
    .from(adminPasskeyChallenges);
  return rows[0]?.total ?? 0;
}
