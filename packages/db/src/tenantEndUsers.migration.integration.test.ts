/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Migration `0014_tenant_end_users` against data a deployment already holds.
 *
 * Before it, every account belonged to one endpoint and usernames were unique per
 * endpoint; after it, accounts belong to the tenant and usernames are unique per
 * tenant. The migration has to move every existing account without losing its
 * identifier (consents, tokens and the audit trail name it), give it access to the
 * endpoint it came from, and resolve two endpoints of one tenant each having an
 * `alice` by renaming the later one rather than merging two people.
 *
 * A scratch database is migrated to the schema before `0014`, seeded with that
 * shape of data in raw SQL (the repositories only know the new schema), and then
 * migrated the rest of the way.
 *
 * Author: John Grimes
 */

import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { sql } from "drizzle-orm";
import {
  cpSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { createDatabase } from "./client.js";
import { applyMigrations, resolveMigrationsFolder } from "./migrations.js";
import { databaseUrlWith } from "./test/connectionUrl.js";
import {
  createScratchDatabase,
  dropScratchDatabase,
} from "./test/scratchDatabase.js";

import type { DatabaseHandle } from "./client.js";
import type { SQL } from "drizzle-orm";

const databaseUrl = process.env["SIGNET_TEST_DATABASE_URL"];
const describeWithDatabase =
  databaseUrl === undefined ? describe.skip : describe;

/** The migration under test, and the last one before it. */
const MIGRATION_TAG = "0014_tenant_end_users";

const SCRATCH = "signet_tenant_end_users_migration";

/** A copy of the migrations folder that stops before {@link MIGRATION_TAG}. */
function foldersBefore(tag: string): string {
  const source = resolveMigrationsFolder();
  const target = mkdtempSync(path.join(tmpdir(), "signet-migrations-"));
  cpSync(source, target, { recursive: true });
  const journalPath = path.join(target, "meta", "_journal.json");
  const journal = JSON.parse(readFileSync(journalPath, "utf8")) as {
    entries: { tag: string }[];
  };
  const cut = journal.entries.findIndex((entry) => entry.tag === tag);
  if (cut === -1) {
    throw new Error(`${tag} is not in the journal`);
  }
  journal.entries = journal.entries.slice(0, cut);
  writeFileSync(journalPath, JSON.stringify(journal));
  return target;
}

describeWithDatabase(`migration ${MIGRATION_TAG}`, () => {
  let owner: DatabaseHandle;
  let scratch: DatabaseHandle;
  let partialFolder: string;

  // Fixed identifiers, so the assertions can name rows directly.
  const tenant = "00000000-0000-4000-8000-000000000001";
  const otherTenant = "00000000-0000-4000-8000-000000000002";
  const ward = "00000000-0000-4000-8000-0000000000a1";
  const clinic = "00000000-0000-4000-8000-0000000000a2";
  const elsewhere = "00000000-0000-4000-8000-0000000000b1";
  const client = "00000000-0000-4000-8000-0000000000c1";
  const wardAlice = "00000000-0000-4000-8000-0000000000d1";
  const clinicAlice = "00000000-0000-4000-8000-0000000000d2";
  const clinicBob = "00000000-0000-4000-8000-0000000000d3";
  const elsewhereAlice = "00000000-0000-4000-8000-0000000000d4";

  /** Runs a query on the scratch database and returns its rows. */
  async function rows<T>(query: SQL): Promise<T[]> {
    return (await scratch.db.execute(query)) as unknown as T[];
  }

  beforeAll(async () => {
    owner = createDatabase({ url: databaseUrl ?? "", maxConnections: 1 });
    await dropScratchDatabase(owner.db, SCRATCH);
    await createScratchDatabase(owner.db, SCRATCH);
    scratch = createDatabase({
      url: databaseUrlWith(databaseUrl ?? "", { database: SCRATCH }),
      maxConnections: 1,
    });

    partialFolder = foldersBefore(MIGRATION_TAG);
    await applyMigrations(scratch.db, partialFolder);

    // Two endpoints in one tenant that each have an `alice`, the clinic's created
    // later, and a third endpoint in another tenant with an `alice` of its own.
    // One statement per call: the driver prepares each, and a prepared statement
    // holds one command.
    for (const statement of [
      sql`
        insert into tenants (id, slug, name) values
                (${tenant}, 'hospital', 'Hospital'),
                (${otherTenant}, 'other', 'Other')
      `,
      sql`
        insert into endpoints (id, tenant_id, slug, name, kind, audience) values
                (${ward}, ${tenant}, 'ward', 'Ward', 'smart', 'https://fhir.example.org/a'),
                (${clinic}, ${tenant}, 'clinic', 'Clinic', 'smart', 'https://fhir.example.org/b'),
                (${elsewhere}, ${otherTenant}, 'main', 'Main', 'smart', 'https://fhir.example.org/c')
      `,
      sql`
        insert into clients (id, endpoint_id, client_id, name, client_type, grant_types)
                values (${client}, ${clinic}, 'clinic-app', 'Clinic app', 'public',
                  '{authorization_code}')
      `,
      sql`
        insert into end_users (id, endpoint_id, username, password_hash, display_name,
                  fhir_user_reference, default_context, created_at) values
                (${wardAlice}, ${ward}, 'alice', '$argon2id$ward', 'Alice (ward)',
                  'Practitioner/ward-1', null, '2026-01-01T00:00:00Z'),
                (${clinicAlice}, ${clinic}, 'alice', '$argon2id$clinic', 'Alice (clinic)',
                  'Practitioner/clinic-1', '{"patient":"p-1"}', '2026-02-01T00:00:00Z'),
                (${clinicBob}, ${clinic}, 'bob', null, 'Bob', null, null, '2026-02-01T00:00:00Z'),
                (${elsewhereAlice}, ${elsewhere}, 'alice', null, 'Alice elsewhere', null, null,
                  '2026-03-01T00:00:00Z')
      `,
      sql`
        insert into consents (endpoint_id, end_user_id, client_id, scope) values
                (${clinic}, ${clinicAlice}, ${client}, 'patient/*.rs')
      `,
      sql`
        insert into end_user_sessions (endpoint_id, end_user_id, token_hash, expires_at)
                values (${clinic}, ${clinicAlice}, 'session-digest', now() + interval '1 day')
      `,
      sql`
        insert into end_user_invitations (endpoint_id, end_user_id, token_hash, expires_at)
                values (${clinic}, ${clinicBob}, 'invitation-digest', now() + interval '1 day')
      `,
    ]) {
      await scratch.db.execute(statement);
    }

    await applyMigrations(scratch.db, resolveMigrationsFolder());
  });

  afterAll(async () => {
    await scratch.close();
    await dropScratchDatabase(owner.db, SCRATCH);
    await owner.close();
    rmSync(partialFolder, { recursive: true, force: true });
  });

  it("moves every account to its endpoint's tenant, keeping its identifier", async () => {
    const moved = await rows<{ id: string; tenant_id: string }>(
      sql`select id, tenant_id from end_users order by id`,
    );
    expect(moved).toEqual([
      { id: wardAlice, tenant_id: tenant },
      { id: clinicAlice, tenant_id: tenant },
      { id: clinicBob, tenant_id: tenant },
      { id: elsewhereAlice, tenant_id: otherTenant },
    ]);
  });

  it("keeps the oldest username and suffixes a later one with its endpoint's slug", async () => {
    const names = await rows<{ id: string; username: string }>(
      sql`select id, username from end_users order by id`,
    );
    expect(names).toEqual([
      { id: wardAlice, username: "alice" },
      { id: clinicAlice, username: "alice@clinic" },
      { id: clinicBob, username: "bob" },
      // Another tenant's `alice` never collided with these, so it keeps its name.
      { id: elsewhereAlice, username: "alice" },
    ]);
  });

  it("keeps each account's password, merging nobody", async () => {
    const hashes = await rows<{ id: string; password_hash: string | null }>(
      sql`select id, password_hash from end_users where tenant_id = ${tenant} order by id`,
    );
    expect(hashes.map((row) => row.password_hash)).toEqual([
      "$argon2id$ward",
      "$argon2id$clinic",
      null,
    ]);
  });

  it("gives each account access to the endpoint it came from, carrying its endpoint fields", async () => {
    const access = await rows<{
      end_user_id: string;
      endpoint_id: string;
      fhir_user_reference: string | null;
      default_context: unknown;
    }>(sql`
      select end_user_id, endpoint_id, fhir_user_reference, default_context
      from end_user_endpoints order by end_user_id
    `);
    expect(access).toEqual([
      {
        end_user_id: wardAlice,
        endpoint_id: ward,
        fhir_user_reference: "Practitioner/ward-1",
        default_context: null,
      },
      {
        end_user_id: clinicAlice,
        endpoint_id: clinic,
        fhir_user_reference: "Practitioner/clinic-1",
        default_context: { patient: "p-1" },
      },
      {
        end_user_id: clinicBob,
        endpoint_id: clinic,
        fhir_user_reference: null,
        default_context: null,
      },
      {
        end_user_id: elsewhereAlice,
        endpoint_id: elsewhere,
        fhir_user_reference: null,
        default_context: null,
      },
    ]);
  });

  it("keeps consents and sessions, which now hang off the access row", async () => {
    expect(
      await rows<{ count: number }>(
        sql`select count(*)::int as count from consents where end_user_id = ${clinicAlice}`,
      ),
    ).toEqual([{ count: 1 }]);

    // Withdrawing the clinic access takes the consent and session with it.
    await scratch.db.execute(
      sql`delete from end_user_endpoints where end_user_id = ${clinicAlice} and endpoint_id = ${clinic}`,
    );
    expect(
      await rows<{ consents: number; sessions: number }>(sql`
        select
          (select count(*)::int from consents where end_user_id = ${clinicAlice}) as consents,
          (select count(*)::int from end_user_sessions where end_user_id = ${clinicAlice}) as sessions
      `),
    ).toEqual([{ consents: 0, sessions: 0 }]);
  });

  it("moves an outstanding invitation to the tenant", async () => {
    expect(
      await rows<{ end_user_id: string; tenant_id: string }>(
        sql`select end_user_id, tenant_id from end_user_invitations`,
      ),
    ).toEqual([{ end_user_id: clinicBob, tenant_id: tenant }]);
  });

  it("refuses a second account with the same username in one tenant", async () => {
    // `execute` returns a lazy query builder; `rows` awaits it into a real promise.
    await expect(
      rows(sql`
        insert into end_users (tenant_id, username, display_name)
        values (${tenant}, 'bob', 'Another Bob')
      `),
    ).rejects.toThrow();
  });
});
