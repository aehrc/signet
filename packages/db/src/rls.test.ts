/**
 * Author: John Grimes
 */

import { getTableName, is } from "drizzle-orm";
import { PgTable } from "drizzle-orm/pg-core";
import { describe, expect, it } from "vitest";

import {
  RLS_EXEMPT_TABLES,
  RLS_TABLES,
  rowLevelSecurityScript,
  rowLevelSecurityStatements,
  TENANT_POLICY_NAME,
  TENANT_SETTING,
} from "./rls.js";
import * as schema from "./schema/index.js";

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
