/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";
import { getTableName, is } from "drizzle-orm";
import { PgTable } from "drizzle-orm/pg-core";

import {
  endpointScopeFromRow,
  executorFor,
  isBoundScope,
  tenantScopeFromRow,
} from "./repositories/scope.js";
import {
  RLS_EXEMPT_TABLES,
  RLS_TABLES,
  rowLevelSecurityScript,
  rowLevelSecurityStatements,
  TENANT_POLICY_NAME,
  TENANT_SETTING,
  withTenantScope,
} from "./rls.js";
import * as schema from "./schema/index.js";
import { createFakeExecutor } from "./test/fakeExecutor.js";

import type { Endpoint } from "./schema/endpoints.js";
import type { Tenant } from "./schema/tenancy.js";

/** Every table the schema actually declares, by its SQL name. */
const schemaTables = Object.values<unknown>(schema)
  .filter((value): value is PgTable => is(value, PgTable))
  .map((table) => getTableName(table))
  .toSorted();

/** Tables whose tenant is reached through their own `endpoint_id`. */
const ONE_HOP_TABLES = [
  "endpoint_keys",
  "idp_configs",
  "end_users",
  "clients",
  "client_requests",
  "policies",
  "launch_contexts",
  "authorization_sessions",
  "access_tokens",
  "refresh_tokens",
  "consents",
];

describe("policy coverage", () => {
  it("finds every table in the schema", () => {
    // Guards the guard: if this ever returned nothing, every assertion below
    // would pass vacuously.
    expect(schemaTables.length).toBeGreaterThan(15);
  });

  it("covers or exempts every table in the schema", () => {
    const covered = new Set([...RLS_TABLES, ...Object.keys(RLS_EXEMPT_TABLES)]);
    const uncovered = schemaTables.filter((table) => !covered.has(table));

    // A new tenant-owned table must either get a policy or be listed as exempt
    // with a reason. Shipping one silently unprotected is the failure this whole
    // module exists to prevent.
    expect(uncovered).toEqual([]);
  });

  it("does not claim a policy for a table that does not exist", () => {
    const known = new Set(schemaTables);
    expect(RLS_TABLES.filter((table) => !known.has(table))).toEqual([]);
    expect(
      Object.keys(RLS_EXEMPT_TABLES).filter((table) => !known.has(table)),
    ).toEqual([]);
  });

  it("never both covers and exempts a table", () => {
    const exempt = new Set(Object.keys(RLS_EXEMPT_TABLES));
    expect(RLS_TABLES.filter((table) => exempt.has(table))).toEqual([]);
  });

  it("gives a reason for every exemption", () => {
    for (const reason of Object.values(RLS_EXEMPT_TABLES)) {
      expect(reason.length).toBeGreaterThan(20);
    }
  });
});

describe("rowLevelSecurityStatements", () => {
  const statements = rowLevelSecurityStatements();
  const text = statements.join("\n");

  it("enables row level security on every covered table", () => {
    for (const table of RLS_TABLES) {
      expect(statements).toContain(
        `alter table ${table} enable row level security`,
      );
    }
  });

  it("creates one named policy per covered table", () => {
    for (const table of RLS_TABLES) {
      const created = statements.filter((statement) =>
        statement.startsWith(
          `create policy ${TENANT_POLICY_NAME} on ${table} `,
        ),
      );
      expect(created).toHaveLength(1);
    }
  });

  it("drops each policy before creating it, so the script is idempotent", () => {
    for (const table of RLS_TABLES) {
      const dropIndex = statements.indexOf(
        `drop policy if exists ${TENANT_POLICY_NAME} on ${table}`,
      );
      const createIndex = statements.findIndex((statement) =>
        statement.startsWith(
          `create policy ${TENANT_POLICY_NAME} on ${table} `,
        ),
      );
      expect(dropIndex).toBeGreaterThanOrEqual(0);
      expect(createIndex).toBeGreaterThan(dropIndex);
    }
  });

  it("reads the tenant from the documented session variable", () => {
    expect(text).toContain(`current_setting('${TENANT_SETTING}', true)`);
  });

  it("asks for the missing-setting case to yield null rather than raise", () => {
    // The `true` second argument is what makes an unset variable produce NULL,
    // and a NULL comparison is not true - so a connection that forgot to set the
    // tenant sees nothing instead of everything.
    const policies = statements.filter((statement) =>
      statement.startsWith("create policy"),
    );
    for (const policy of policies) {
      expect(policy).toContain(`current_setting('${TENANT_SETTING}', true)`);
      expect(policy).not.toMatch(/current_setting\('[^']+'\)/);
    }
  });

  it("guards against an empty setting, which would fail the uuid cast", () => {
    expect(text).toContain(
      `nullif(current_setting('${TENANT_SETTING}', true), '')::uuid`,
    );
  });

  it("scopes each one-hop table through its own endpoint column", () => {
    // A copy-pasted predicate naming the wrong table would still compile, still
    // run, and permit everything.
    for (const table of ONE_HOP_TABLES) {
      const policy = statements.find((statement) =>
        statement.startsWith(
          `create policy ${TENANT_POLICY_NAME} on ${table} `,
        ),
      );
      expect(policy).toBeDefined();
      expect(policy).toContain(`e.id = ${table}.endpoint_id`);
    }
  });

  it("scopes authorization codes through their session's endpoint", () => {
    const policy = statements.find((statement) =>
      statement.startsWith(
        `create policy ${TENANT_POLICY_NAME} on authorization_codes `,
      ),
    );
    expect(policy).toContain("s.id = authorization_codes.session_id");
    expect(policy).toContain("join endpoints e on e.id = s.endpoint_id");
  });

  it("scopes the client-owned tables through their client's endpoint", () => {
    for (const table of ["client_policy_overrides", "jti_replay"]) {
      const policy = statements.find((statement) =>
        statement.startsWith(
          `create policy ${TENANT_POLICY_NAME} on ${table} `,
        ),
      );
      expect(policy).toContain(`c.id = ${table}.client_id`);
      expect(policy).toContain("join endpoints e on e.id = c.endpoint_id");
    }
  });

  it("applies to writes as well as reads", () => {
    for (const statement of statements.filter((s) =>
      s.startsWith("create policy"),
    )) {
      expect(statement).toContain("for all using (");
    }
  });

  it("does not force the policies on the table owner by default", () => {
    expect(text).not.toContain("force row level security");
  });

  it("forces them when asked, for a deployment that runs sweeps elsewhere", () => {
    const forced = rowLevelSecurityStatements({ force: true });
    for (const table of RLS_TABLES) {
      expect(forced).toContain(`alter table ${table} force row level security`);
    }
  });
});

describe("rowLevelSecurityScript", () => {
  it("terminates every statement", () => {
    const script = rowLevelSecurityScript();
    const lines = script.trimEnd().split("\n");
    expect(lines.length).toBeGreaterThan(RLS_TABLES.length);
    expect(script.endsWith(";\n")).toBe(true);
  });
});

describe("withTenantScope", () => {
  const AT = new Date("2026-01-01T00:00:00.000Z");
  const tenant: Tenant = {
    id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    slug: "demo",
    name: "Demo",
    createdAt: AT,
    updatedAt: AT,
  };
  /** An endpoint row reduced to what the scope constructors read. */
  const endpoint = {
    id: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
    tenantId: tenant.id,
    slug: "e1",
  } as Endpoint;

  it("hands the work a scope bound to the transaction it opened", async () => {
    const fake = createFakeExecutor();
    const scope = tenantScopeFromRow(tenant);

    await withTenantScope(fake.db, scope, (inner) => {
      expect(isBoundScope(inner)).toBe(true);
      expect(inner.tenantId).toBe(tenant.id);
      // The transaction, not the connection: a bound scope that carried the pool
      // would issue its reads outside the transaction that declared the tenant.
      expect(executorFor(inner)).toBe(fake.transactions[0]!);
      return Promise.resolve(undefined);
    });

    expect(fake.transactions).toHaveLength(1);
  });

  it("declares the tenant inside that transaction, as a parameter", async () => {
    const fake = createFakeExecutor();

    await withTenantScope(fake.db, tenantScopeFromRow(tenant), () =>
      Promise.resolve(undefined),
    );

    expect(fake.statements).toEqual([
      {
        text: "select set_config($1, $2, true)",
        params: [TENANT_SETTING, tenant.id],
      },
    ]);
    // The uuid must not appear in the SQL text; see the module header.
    expect(fake.statements[0]?.text).not.toContain(tenant.id);
  });

  it("asks for a transaction-local declaration, which cannot outlive the work", async () => {
    const fake = createFakeExecutor();

    await withTenantScope(fake.db, tenantScopeFromRow(tenant), () =>
      Promise.resolve(undefined),
    );

    // `set_config(..., true)` is released when the transaction ends, so the next
    // request to borrow this pooled connection inherits nothing. That it is
    // actually gone afterwards is asserted against a real database in
    // `rls.enforcement.integration.test.ts`.
    expect(fake.statements[0]?.text.endsWith(", true)")).toBe(true);
  });

  it("keeps the scope's narrowing, so an endpoint scope stays one", async () => {
    const fake = createFakeExecutor();
    const endpointScope = endpointScopeFromRow(
      tenantScopeFromRow(tenant),
      endpoint,
    );

    await withTenantScope(fake.db, endpointScope, (inner) => {
      expect(inner.endpointId).toBe(endpoint.id);
      expect(isBoundScope(inner)).toBe(true);
      return Promise.resolve(undefined);
    });
  });

  it("reuses an existing binding rather than declaring a second time", async () => {
    const fake = createFakeExecutor();

    await withTenantScope(
      fake.db,
      tenantScopeFromRow(tenant),
      async (outer) => {
        const inner = await withTenantScope(fake.db, outer, (nested) =>
          Promise.resolve(nested),
        );

        // The property FR-006 names: a data-layer function calling another must
        // reuse the tenant already declared rather than opening a second
        // transaction.
        expect(inner).toBe(outer);
      },
    );

    expect(fake.transactions).toHaveLength(1);
    expect(fake.statements).toHaveLength(1);
  });

  it("stops the scope claiming a declaration once the transaction ends", async () => {
    const fake = createFakeExecutor();

    const spent = await withTenantScope(
      fake.db,
      tenantScopeFromRow(tenant),
      (inner) => Promise.resolve(inner),
    );

    // `set_config(..., true)` dies with the transaction, so a scope that still
    // claimed to carry one would issue its statements on the pooled connection
    // with no tenant declared - an empty read and a refused write, silently.
    expect(isBoundScope(spent)).toBe(false);
    expect(() => executorFor(spent)).toThrow(/has ended/);
  });

  it("declares again for a scope resolved in an earlier transaction", async () => {
    const fake = createFakeExecutor();

    // The ordinary shape of the OAuth code: a client is resolved inside one
    // transaction and used in the next. The proof the scope carries outlives the
    // declaration made from it, so the second call declares rather than refusing.
    const resolved = await withTenantScope(
      fake.db,
      tenantScopeFromRow(tenant),
      (inner) => Promise.resolve(inner),
    );

    await withTenantScope(fake.db, resolved, (inner) => {
      expect(isBoundScope(inner)).toBe(true);
      expect(executorFor(inner)).toBe(fake.transactions[1]!);
      return Promise.resolve(undefined);
    });

    expect(fake.transactions).toHaveLength(2);
    expect(fake.statements).toHaveLength(2);
  });

  it("closes the declaration even when the work throws", async () => {
    const fake = createFakeExecutor();
    let captured: Awaited<ReturnType<typeof declareCapture>> | undefined;

    /** Hands the bound scope out through a closure, since the call will reject. */
    function declareCapture(scope: Parameters<typeof isBoundScope>[0]) {
      return Promise.resolve(scope);
    }

    await expect(
      withTenantScope(fake.db, tenantScopeFromRow(tenant), async (inner) => {
        captured = await declareCapture(inner);
        throw new Error("the work failed");
      }),
    ).rejects.toThrow("the work failed");

    // A rolled-back transaction releases the setting exactly as a committed one
    // does, so a scope left behind by a failure must not claim otherwise.
    expect(captured).toBeDefined();
    expect(captured !== undefined && isBoundScope(captured)).toBe(false);
  });
});
