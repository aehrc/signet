/**
 * Proves the tenant isolation policies are actually installed by a migration.
 *
 * `rls.test.ts` asserts the policy *statements* are correct. That is a different
 * claim from the one this file makes, and the difference is the whole point: a
 * generator that produces perfect SQL nobody ever runs protects nothing. Before
 * this suite existed, `applyRowLevelSecurity` was called from exactly one place -
 * a test fixture - so every deployed database had the policies the documentation
 * described and none of the policies themselves.
 *
 * So these tests read the migration folder, which is the artefact the `migrate`
 * command applies and the Helm chart's pre-upgrade hook runs, and assert the
 * policies are in it. A new tenant-owned table added to `rls.ts` without a
 * migration that creates its policy fails here.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

import { resolveMigrationsFolder } from "./migrations.js";
import { RLS_TABLES, TENANT_POLICY_NAME, TENANT_SETTING } from "./rls.js";

/** The migration folder the `migrate` command would apply. */
const folder = resolveMigrationsFolder();

/** Every generated migration, newest last, as one searchable body of SQL. */
const migrationSql = readdirSync(folder)
  .filter((name) => name.endsWith(".sql"))
  .toSorted()
  .map((name) => readFileSync(path.join(folder, name), "utf8"))
  .join("\n")
  .toLowerCase();

/** The journal the migrator reads to decide what to run. */
const journal = JSON.parse(
  readFileSync(path.join(folder, "meta", "_journal.json"), "utf8"),
) as { readonly entries: readonly { readonly tag: string }[] };

describe("the migration folder", () => {
  it("contains migrations at all", () => {
    // Guards the guard. If the folder resolved somewhere empty, every assertion
    // below would pass against an empty string.
    expect(migrationSql.length).toBeGreaterThan(1000);
    expect(journal.entries.length).toBeGreaterThan(0);
  });

  it("runs every SQL file it ships", () => {
    // A migration file that is not in the journal is never applied. It would sit
    // in the repository looking like protection that does not exist, which is the
    // exact failure this suite was written for.
    const tags = new Set(journal.entries.map((entry) => entry.tag));
    const orphans = readdirSync(folder)
      .filter((name) => name.endsWith(".sql"))
      .map((name) => name.replace(/\.sql$/, ""))
      .filter((tag) => !tags.has(tag));

    expect(orphans).toEqual([]);
  });
});

describe("tenant isolation is installed by migration", () => {
  it.each([...RLS_TABLES])("enables row level security on %s", (table) => {
    expect(migrationSql).toContain(
      `alter table ${table} enable row level security`,
    );
  });

  it.each([...RLS_TABLES])("creates the isolation policy on %s", (table) => {
    expect(migrationSql).toContain(
      `create policy ${TENANT_POLICY_NAME} on ${table} for all using (`,
    );
  });

  it.each([...RLS_TABLES])(
    "scopes %s to the current tenant setting",
    (table) => {
      // The policy must read the session variable. A policy created with, say,
      // `using (true)` would satisfy the two assertions above and isolate nothing,
      // so the predicate itself is checked rather than merely its existence.
      const policy = migrationSql.slice(
        migrationSql.indexOf(
          `create policy ${TENANT_POLICY_NAME} on ${table} for all using (`,
        ),
      );
      const statement = policy.slice(0, policy.indexOf(";"));

      expect(statement).toContain(`current_setting('${TENANT_SETTING}', true)`);
    },
  );
});
