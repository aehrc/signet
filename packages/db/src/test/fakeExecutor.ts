/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * A database handle that records statements instead of issuing them.
 *
 * The tenant declaration is worth asserting precisely: that it is issued inside a
 * transaction, that the tenant travels as a parameter rather than as SQL text, and
 * that it asks Postgres for a transaction-local setting. All three are properties
 * of the statement itself, so they are asserted here without a database - and the
 * integration suites assert the consequence, which is that the setting is gone
 * once the transaction ends.
 *
 * Statements are rendered through Drizzle's own dialect rather than inspected as
 * template chunks, so what a test sees is what the driver would have sent.
 *
 * Author: John Grimes
 */

import { PgDialect } from "drizzle-orm/pg-core";

import type { Executor } from "../repositories/executor.js";
import type { SQL } from "drizzle-orm";

/** A statement as the driver would have received it. */
export interface RecordedStatement {
  /** The SQL text, with placeholders in place of values. */
  readonly text: string;
  /** The values bound to those placeholders, in order. */
  readonly params: readonly unknown[];
}

/** A recording handle and what it observed. */
export interface FakeExecutor {
  /** The handle to pass where an {@link Executor} is required. */
  readonly db: Executor;
  /** Every statement issued, in order, on the handle or on a transaction. */
  readonly statements: readonly RecordedStatement[];
  /** One entry per transaction opened, in order, so identity can be asserted. */
  readonly transactions: readonly Executor[];
}

/** Renders a statement the way the driver would; see the module documentation. */
const dialect = new PgDialect();

/**
 * Creates a handle that records rather than executes.
 *
 * Every query returns an empty result, which is enough for the declaration path:
 * `set_config` is issued for its effect, and a caller that reads rows needs a real
 * database rather than a fake.
 *
 * @returns The handle, and the live arrays it records into.
 * @example
 * ```ts
 * const fake = createFakeExecutor();
 * await withTenantScope(fake.db, scope, async () => undefined);
 * expect(fake.statements[0]?.params).toContain(scope.tenantId);
 * ```
 */
export function createFakeExecutor(): FakeExecutor {
  const statements: RecordedStatement[] = [];
  const transactions: Executor[] = [];

  const execute = async (query: SQL): Promise<readonly unknown[]> => {
    const { sql: text, params } = dialect.sqlToQuery(query);
    statements.push({ text, params });
    return await Promise.resolve([]);
  };

  const transaction = async <T>(
    work: (tx: Executor) => Promise<T>,
  ): Promise<T> => {
    // A distinct handle per transaction, so a test can assert that a bound scope
    // carries the transaction it was declared on rather than the connection.
    const tx = { execute } as unknown as Executor;
    transactions.push(tx);
    return await work(tx);
  };

  return {
    db: { execute, transaction } as unknown as Executor,
    statements,
    transactions,
  };
}
