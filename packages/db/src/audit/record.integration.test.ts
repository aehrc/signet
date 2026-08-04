/**
 * Audit log behaviour that only Postgres can confirm.
 *
 * The unit tests assert the SQL that keyset pagination generates; only a real
 * server can confirm that the row-value comparison and its casts actually page
 * without skipping or repeating a row - which is the whole point of paging this
 * way, and the kind of thing that a plausible-looking predicate gets wrong.
 *
 * Skipped unless `SIGNET_TEST_DATABASE_URL` names a throwaway database. CI has
 * none yet, and a suite that tries to connect regardless would fail the build.
 *
 * Author: John Grimes
 */

import { eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import { fileURLToPath } from "node:url";
import postgres from "postgres";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { queryAuditEvents, recordAuditEvent } from "./record.js";
import { tenantScopeFromRow } from "../repositories/scope.js";
import { withTenantScope } from "../rls.js";
import { auditEvents } from "../schema/audit.js";
import { tenants } from "../schema/tenancy.js";
import { isTestSchemaReady } from "../test/schemaReady.js";

import type { AuditEventCursor } from "./record.js";
import type { Executor } from "../repositories/executor.js";
import type { TenantScope } from "../repositories/scope.js";

const databaseUrl = process.env.SIGNET_TEST_DATABASE_URL;

const describeWithDatabase =
  databaseUrl === undefined ? describe.skip : describe;

const migrationsFolder = fileURLToPath(
  new URL("../../drizzle", import.meta.url),
);

/**
 * Lock key for serialising migrations across test files.
 *
 * Vitest runs files in parallel, and two processes applying the same migration
 * folder at once is a race. An arbitrary constant is enough: nothing else in the
 * product takes a session-level advisory lock.
 */
const MIGRATION_LOCK_KEY = 5_348_464;

describeWithDatabase("the audit log against Postgres", () => {
  let sql: ReturnType<typeof postgres> | undefined;
  let connection: ReturnType<typeof drizzle>;
  let db: Executor;
  let tenantId: string | undefined;
  let tenantScope: TenantScope | undefined;

  beforeAll(async () => {
    sql = postgres(databaseUrl ?? "", { max: 2, onnotice: () => {} });
    connection = drizzle(sql);

    // Normally already migrated by the Vitest global setup, which runs before any
    // worker starts so that no DDL takes table locks while another worker holds row
    // locks on the same tables. The fallback covers running this file on its own.
    if (!isTestSchemaReady()) {
      await sql`select pg_advisory_lock(${MIGRATION_LOCK_KEY})`;
      try {
        await migrate(connection, { migrationsFolder });
      } finally {
        await sql`select pg_advisory_unlock(${MIGRATION_LOCK_KEY})`;
      }
    }

    // `drizzle(sql)` infers `Record<string, unknown>` for its schema type
    // parameter while `Executor` pins `Record<string, never>`, so the two differ
    // in a phantom type only. The query surface used here is identical.
    db = connection as unknown as Executor;

    const inserted = await connection
      .insert(tenants)
      .values({ slug: `audit-${Date.now()}`, name: "Audit test tenant" })
      .returning();
    const [tenant] = inserted;
    if (tenant === undefined) {
      throw new Error("failed to create the test tenant");
    }
    tenantId = tenant.id;
    tenantScope = tenantScopeFromRow(tenant);
  }, 60_000);

  afterAll(async () => {
    if (sql === undefined) {
      return;
    }
    // Cascades through audit_events, so the database is left as it was found.
    if (tenantId !== undefined) {
      await connection.delete(tenants).where(eq(tenants.id, tenantId));
    }
    await sql.end();
  });

  /**
   * The tenant created in `beforeAll`.
   *
   * Narrowed here rather than at every use: `beforeAll` throws if it could not
   * create one, so a test body only ever sees a real identifier.
   */
  function testTenantId(): string {
    if (tenantId === undefined) {
      throw new Error("the test tenant was not created");
    }
    return tenantId;
  }

  /**
   * Reads a page of the test tenant's trail.
   *
   * `queryAuditEvents` takes the tenant from a bound scope rather than from the
   * filter, so every read here goes through one, and the filter cannot name a
   * tenant of its own.
   */
  async function readAudit(filter: Parameters<typeof queryAuditEvents>[1]) {
    if (tenantScope === undefined) {
      throw new Error("the test tenant was not created");
    }
    return await withTenantScope(db, tenantScope, (bound) =>
      queryAuditEvents(bound, filter),
    );
  }

  it("persists a redacted row that reads back as the domain shape", async () => {
    await recordAuditEvent(db, {
      tenantId: testTenantId(),
      actor: { type: "admin-user", id: "u1", displayName: "Dr Alice Smith" },
      action: "client.secret-rotated",
      target: { type: "client", id: "app-1" },
      endpointSlug: "pathling",
      detail: { clientId: "app-1", client_secret: "s3cr3t" },
      ip: "203.0.113.7",
      userAgent: "curl/8.5.0",
      at: new Date("2026-05-01T09:00:00.000Z"),
    });

    const page = await readAudit({
      actions: ["client.secret-rotated"],
    });

    expect(page.events).toHaveLength(1);
    const [event] = page.events;
    expect(event?.actorType).toBe("admin-user");
    expect(event?.action).toBe("client.secret-rotated");
    expect(event?.targetType).toBe("client");
    expect(event?.detail).toEqual({
      clientId: "app-1",
      client_secret: "[redacted]",
      actorDisplayName: "Dr Alice Smith",
      endpointSlug: "pathling",
    });
    expect(event?.at).toEqual(new Date("2026-05-01T09:00:00.000Z"));
  });

  it("stamps the row from the database clock when no time is given", async () => {
    const before = new Date();
    await recordAuditEvent(db, {
      tenantId: testTenantId(),
      actor: { type: "system" },
      action: "key.rotated",
    });

    const page = await readAudit({
      actions: ["key.rotated"],
    });

    const at = page.events[0]?.at;
    expect(at).toBeInstanceOf(Date);
    expect(at?.getTime()).toBeGreaterThanOrEqual(before.getTime() - 1000);
  });

  it("pages by keyset over rows sharing one timestamp", async () => {
    // One timestamp for every row: this is the case a cursor on time alone gets
    // wrong, either repeating the boundary row or skipping past it.
    const at = new Date("2026-06-01T00:00:00.000Z");
    for (let index = 0; index < 7; index += 1) {
      await recordAuditEvent(db, {
        tenantId: testTenantId(),
        actor: { type: "client", id: `c${index}` },
        action: "token.introspected",
        detail: { index },
        at,
      });
    }

    const collected: string[] = [];
    let cursor: AuditEventCursor | undefined;
    let pages = 0;

    do {
      const page = await readAudit({
        actions: ["token.introspected"],
        limit: 3,
        ...(cursor === undefined ? {} : { after: cursor }),
      });
      collected.push(...page.events.map((event) => event.id));
      cursor = page.nextCursor ?? undefined;
      pages += 1;
      expect(pages).toBeLessThan(10);
    } while (cursor !== undefined);

    expect(collected).toHaveLength(7);
    expect(new Set(collected).size).toBe(7);
  });

  it("reads the trail forwards as well as backwards", async () => {
    const forwards = await readAudit({
      order: "oldest-first",
      limit: 200,
    });
    const backwards = await readAudit({
      limit: 200,
    });

    expect(forwards.events.map((event) => event.id)).toEqual(
      backwards.events.map((event) => event.id).toReversed(),
    );
  });

  it("filters by half-open time range", async () => {
    const page = await readAudit({
      from: new Date("2026-06-01T00:00:00.000Z"),
      until: new Date("2026-06-01T00:00:00.001Z"),
      limit: 200,
    });

    expect(page.events).toHaveLength(7);
    for (const event of page.events) {
      expect(event.action).toBe("token.introspected");
    }
  });

  it("never returns another tenant's events", async () => {
    const [other] = await connection
      .insert(tenants)
      .values({ slug: `audit-other-${Date.now()}`, name: "Other tenant" })
      .returning({ id: tenants.id });
    if (other === undefined) {
      throw new Error("failed to create the second tenant");
    }

    try {
      await recordAuditEvent(db, {
        tenantId: other.id,
        actor: { type: "system" },
        action: "tenant.created",
      });

      const mine = await readAudit({
        limit: 200,
      });
      expect(
        mine.events.some((event) => event.action === "tenant.created"),
      ).toBe(false);
    } finally {
      await connection.delete(tenants).where(eq(tenants.id, other.id));
    }
  });

  it("does not throw when the insert cannot succeed", async () => {
    const failures: unknown[] = [];

    // A tenant that does not exist violates the foreign key, which is as close
    // as a test can get to the database refusing a write in production.
    await expect(
      recordAuditEvent(
        db,
        {
          tenantId: "00000000-0000-4000-8000-000000000000",
          actor: { type: "system" },
          action: "token.denied",
        },
        (failure) => failures.push(failure.error),
      ),
    ).resolves.toBeUndefined();

    expect(failures).toHaveLength(1);

    // The connection must still be usable afterwards: an audit failure that
    // poisoned the pool would take the whole server down with it.
    await expect(
      connection.select().from(auditEvents).limit(1),
    ).resolves.toBeDefined();
  });
});
