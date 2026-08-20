/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Where "now" comes from.
 *
 * Expiry decisions in this directory are made by the database, not by the
 * process clock. A conditional `UPDATE ... WHERE expires_at > now()` decides and
 * acts in one statement, so there is no window in which a credential is judged
 * live and then honoured after it has expired - and no dependence on the
 * application server's clock agreeing with Postgres, which it will not, because
 * several application servers share one database.
 *
 * Every function that compares against time therefore takes an optional `now`
 * and defaults to the database's own `now()`. The parameter exists so that a
 * test can pin the instant, and so that a caller who has already read
 * `databaseNow()` for an audit event can make several statements agree on one
 * timestamp. It is not there so that a handler can pass `new Date()`.
 *
 * Author: John Grimes
 */

import { sql } from "drizzle-orm";

import type { SQL } from "drizzle-orm";

/**
 * Resolves an optional caller-supplied instant to a comparable SQL value.
 *
 * `now()` in Postgres is the start of the current transaction, which is what
 * makes several statements inside one transaction agree about expiry.
 *
 * @param now - An explicit instant, or undefined to use the transaction time.
 */
export function nowValue(now?: Date): Date | SQL<unknown> {
  return now ?? sql`now()`;
}
