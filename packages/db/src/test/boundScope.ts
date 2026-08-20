/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * A bound scope over a handle of the test's choosing.
 *
 * A bound scope cannot be written down: the brand and the transaction it carries
 * are module-private to `../repositories/scope.ts`, which is what stops a query
 * with no declared tenant from compiling. A unit test that drives a data-layer
 * function against a recording or stubbing handle still needs one, and it needs it
 * without a database.
 *
 * So this goes through {@link declareTenantScope}, the same function the real path
 * uses. The handle is asked to issue the declaration exactly as Postgres would be,
 * which means a fake that records statements records this one too - and a test
 * asserting on the declaration is asserting on the real thing rather than on a
 * fixture that resembles it.
 *
 * Author: John Grimes
 */

import {
  declareTenantScope,
  tenantScopeFromRow,
} from "../repositories/scope.js";

import type { Executor } from "../repositories/executor.js";
import type { BoundTenantScope } from "../repositories/scope.js";

/** Which tenant a test scope names. */
export interface TestTenant {
  readonly id: string;
  readonly slug?: string;
}

/**
 * Declares a tenant on a handle and returns the bound scope.
 *
 * @param db - The handle to declare on, typically a fake or a stub.
 * @param tenant - The tenant the scope names.
 * @returns The scope, bound to `db`.
 * @example
 * ```ts
 * const bound = await boundScopeOver(selectingExecutor(rows, capture), {
 *   id: TENANT_ID,
 * });
 * const page = await queryAuditEvents(bound, { limit: 2 });
 * ```
 */
export async function boundScopeOver(
  db: Executor,
  tenant: TestTenant,
): Promise<BoundTenantScope> {
  return await declareTenantScope(
    db,
    tenantScopeFromRow({
      id: tenant.id,
      slug: tenant.slug ?? "test-tenant",
      name: "Test tenant",
      createdAt: new Date(0),
      updatedAt: new Date(0),
    }),
  );
}
