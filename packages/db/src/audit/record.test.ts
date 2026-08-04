/**
 * Author: John Grimes
 */

import { PgDialect } from "drizzle-orm/pg-core";
import { describe, expect, it, vi } from "vitest";

import {
  AUDIT_DETAIL_RESERVED_KEYS,
  auditEventCursorOf,
  buildAuditEventPredicate,
  buildAuditEventRow,
  createAuditRecorder,
  DEFAULT_AUDIT_PAGE_SIZE,
  MAX_AUDIT_PAGE_SIZE,
  normaliseAuditPageSize,
  queryAuditEvents,
  recordAuditEvent,
  toAuditEventRecord,
  type AuditEventFilter,
} from "./record.js";
import { REDACTED_MARKER } from "./redact.js";
import { boundScopeOver } from "../test/boundScope.js";

import type { AuditEventInput } from "./events.js";
import type { Executor } from "../repositories/executor.js";
import type { AuditEvent, NewAuditEvent } from "../schema/audit.js";
import type { SQL } from "drizzle-orm";

const TENANT_ID = "11111111-1111-4111-8111-111111111111";
const ENDPOINT_ID = "22222222-2222-4222-8222-222222222222";

const dialect = new PgDialect();

/** Renders a predicate to SQL text and parameters, with no database. */
function render(predicate: SQL): { text: string; params: unknown[] } {
  const query = dialect.sqlToQuery(predicate);
  return { text: query.sql, params: [...query.params] };
}

/** A minimal event, for tests that only care about one field. */
function anEvent(overrides: Partial<AuditEventInput> = {}): AuditEventInput {
  return {
    tenantId: TENANT_ID,
    actor: { type: "system" },
    action: "token.issued",
    ...overrides,
  };
}

/** An executor whose only capability is to accept an insert. */
function insertingExecutor(sink: {
  rows: NewAuditEvent[];
  fail?: Error;
  /** Values bound by every statement the handle was asked to issue. */
  declared?: unknown[][];
}): Executor {
  const dialect = new PgDialect();
  const transaction = {
    execute: (query: SQL) => {
      sink.declared?.push([...dialect.sqlToQuery(query).params]);
      return Promise.resolve([]);
    },
    insert: () => ({
      values: (row: NewAuditEvent) => {
        if (sink.fail !== undefined) {
          return Promise.reject(sink.fail);
        }
        sink.rows.push(row);
        return Promise.resolve();
      },
    }),
  };

  // The insert opens its own transaction to declare the event's tenant, so a
  // handle that cannot open one is not a handle `recordAuditEvent` accepts.
  return {
    transaction: (work: (tx: Executor) => Promise<unknown>) =>
      work(transaction as unknown as Executor),
  } as unknown as Executor;
}

interface SelectCapture {
  predicate?: SQL;
  order?: unknown[];
  limit?: number;
}

/** An executor that replays a fixed row set and records how it was asked. */
function selectingExecutor(
  rows: readonly AuditEvent[],
  capture: SelectCapture,
): Executor {
  const chain = {
    from: () => chain,
    where: (predicate: SQL) => {
      capture.predicate = predicate;
      return chain;
    },
    orderBy: (...order: unknown[]) => {
      capture.order = order;
      return chain;
    },
    limit: (limit: number) => {
      capture.limit = limit;
      return Promise.resolve([...rows]);
    },
  };

  return {
    select: () => chain,
    // Present so that a bound scope can be declared over this handle; see
    // `../test/boundScope.ts`.
    execute: () => Promise.resolve([]),
  } as unknown as Executor;
}

/** A bound scope over a stubbing handle, for the read paths. */
async function selecting(
  rows: readonly AuditEvent[],
  capture: SelectCapture = {},
) {
  return await boundScopeOver(selectingExecutor(rows, capture), {
    id: TENANT_ID,
  });
}

/** A stored row, for the read paths. */
function aRow(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    id: "33333333-3333-4333-8333-333333333333",
    tenantId: TENANT_ID,
    endpointId: ENDPOINT_ID,
    actorType: "admin_user",
    actorId: "44444444-4444-4444-8444-444444444444",
    action: "endpoint.updated",
    targetType: "endpoint",
    targetId: ENDPOINT_ID,
    detail: {},
    ip: "203.0.113.7",
    userAgent: "curl/8.5.0",
    at: new Date("2026-05-01T09:00:00.000Z"),
    ...overrides,
  };
}

describe("buildAuditEventRow", () => {
  it("redacts the detail blob, so there is no unredacted write path", () => {
    const row = buildAuditEventRow(
      anEvent({ detail: { clientId: "app-1", client_secret: "s3cr3t" } }),
    );

    expect(row.detail).toEqual({
      clientId: "app-1",
      client_secret: REDACTED_MARKER,
    });
  });

  it("records an empty blob when the call site supplies no detail", () => {
    expect(buildAuditEventRow(anEvent()).detail).toEqual({});
  });

  it("overwrites reserved detail keys with the writer's own values", () => {
    const row = buildAuditEventRow(
      anEvent({
        actor: { type: "admin-user", id: "u1", displayName: "Dr Alice Smith" },
        endpointSlug: "pathling",
        detail: {
          [AUDIT_DETAIL_RESERVED_KEYS.actorDisplayName]: "Someone Else",
          [AUDIT_DETAIL_RESERVED_KEYS.endpointSlug]: "not-this-one",
        },
      }),
    );

    expect(row.detail).toEqual({
      actorDisplayName: "Dr Alice Smith",
      endpointSlug: "pathling",
    });
  });

  it("omits the reserved keys when the caller has nothing to put in them", () => {
    expect(
      buildAuditEventRow(anEvent({ actor: { type: "client" } })).detail,
    ).toEqual({});
  });

  it("runs a display name through the credential check", () => {
    const row = buildAuditEventRow(
      anEvent({ actor: { type: "client", displayName: "Bearer abcdefgh" } }),
    );

    expect(row.detail).toEqual({ actorDisplayName: REDACTED_MARKER });
  });

  it("spells the actor type the way the column does", () => {
    expect(
      buildAuditEventRow(anEvent({ actor: { type: "api-token" } })).actorType,
    ).toBe("api_token");
    expect(
      buildAuditEventRow(anEvent({ actor: { type: "end-user" } })).actorType,
    ).toBe("end_user");
  });

  it("nulls every field the caller left out", () => {
    const row = buildAuditEventRow(anEvent());

    expect(row.endpointId).toBeNull();
    expect(row.actorId).toBeNull();
    expect(row.targetType).toBeNull();
    expect(row.targetId).toBeNull();
    expect(row.ip).toBeNull();
    expect(row.userAgent).toBeNull();
  });

  it("carries the target through", () => {
    const row = buildAuditEventRow(
      anEvent({ target: { type: "client", id: "app-1" } }),
    );

    expect(row.targetType).toBe("client");
    expect(row.targetId).toBe("app-1");
  });

  it("leaves the timestamp to Postgres unless the caller names one", () => {
    expect("at" in buildAuditEventRow(anEvent())).toBe(false);

    const at = new Date("2026-04-01T12:00:00.000Z");
    expect(buildAuditEventRow(anEvent({ at })).at).toBe(at);
  });

  it("caps a hostile user agent and trims whitespace", () => {
    const row = buildAuditEventRow(
      anEvent({ userAgent: `  ${"A".repeat(5000)}  `, ip: " 203.0.113.7 " }),
    );

    expect(row.userAgent).toHaveLength(512);
    expect(row.ip).toBe("203.0.113.7");
  });

  it("treats a blank header as absent", () => {
    const row = buildAuditEventRow(anEvent({ userAgent: "   ", ip: "" }));

    expect(row.userAgent).toBeNull();
    expect(row.ip).toBeNull();
  });
});

describe("recordAuditEvent", () => {
  it("inserts the redacted row", async () => {
    const sink = { rows: [] as NewAuditEvent[] };

    await recordAuditEvent(
      insertingExecutor(sink),
      anEvent({
        action: "client.secret-rotated",
        detail: { secret: "s3cr3t" },
      }),
    );

    expect(sink.rows).toHaveLength(1);
    expect(sink.rows[0]?.action).toBe("client.secret-rotated");
    expect(sink.rows[0]?.detail).toEqual({ secret: REDACTED_MARKER });
  });

  it("declares the event's own tenant before inserting", async () => {
    // The write is tenant-owned, so it needs a declared tenant, and it must not
    // borrow the audited operation's transaction - a failed insert aborts the
    // transaction that issued it, which is the one thing this function exists to
    // avoid. So it declares for itself, from the tenant the event names.
    const sink = { rows: [] as NewAuditEvent[], declared: [] as unknown[][] };

    await recordAuditEvent(insertingExecutor(sink), anEvent());

    expect(sink.declared).toHaveLength(1);
    expect(sink.declared[0]).toContain(TENANT_ID);
    expect(sink.rows).toHaveLength(1);
  });

  it("never fails the operation being audited", async () => {
    const reportFailure = vi.fn();
    const failure = new Error("connection terminated");

    await expect(
      recordAuditEvent(
        insertingExecutor({ rows: [], fail: failure }),
        anEvent({ action: "authorize.denied" }),
        reportFailure,
      ),
    ).resolves.toBeUndefined();

    expect(reportFailure).toHaveBeenCalledTimes(1);
    expect(reportFailure.mock.calls[0]?.[0]).toMatchObject({
      action: "authorize.denied",
      tenantId: TENANT_ID,
      error: failure,
    });
  });

  it("hands the reporter a redacted row, not the caller's blob", async () => {
    const reportFailure = vi.fn();

    await recordAuditEvent(
      insertingExecutor({ rows: [], fail: new Error("down") }),
      anEvent({ detail: { password: "hunter2" } }),
      reportFailure,
    );

    const failure = reportFailure.mock.calls[0]?.[0] as {
      row: NewAuditEvent;
    };
    expect(failure.row.detail).toEqual({ password: REDACTED_MARKER });
    expect(JSON.stringify(failure.row)).not.toContain("hunter2");
  });

  it("survives a reporter that throws, because there is nowhere left to go", async () => {
    await expect(
      recordAuditEvent(
        insertingExecutor({ rows: [], fail: new Error("down") }),
        anEvent(),
        () => {
          throw new Error("the log aggregator is down too");
        },
      ),
    ).resolves.toBeUndefined();
  });
});

describe("createAuditRecorder", () => {
  it("binds the reporter so no call site has to remember it", async () => {
    const reportFailure = vi.fn();
    const recorder = createAuditRecorder(reportFailure);

    await recorder.record(
      insertingExecutor({ rows: [], fail: new Error("down") }),
      anEvent(),
    );

    expect(reportFailure).toHaveBeenCalledTimes(1);
  });
});

describe("normaliseAuditPageSize", () => {
  it("defaults when unasked", () => {
    expect(normaliseAuditPageSize(undefined)).toBe(DEFAULT_AUDIT_PAGE_SIZE);
  });

  it("keeps a sensible request", () => {
    expect(normaliseAuditPageSize(25)).toBe(25);
  });

  it("clamps an oversized request", () => {
    expect(normaliseAuditPageSize(10_000)).toBe(MAX_AUDIT_PAGE_SIZE);
  });

  it("tolerates nonsense from a query string", () => {
    expect(normaliseAuditPageSize(0)).toBe(DEFAULT_AUDIT_PAGE_SIZE);
    expect(normaliseAuditPageSize(-5)).toBe(DEFAULT_AUDIT_PAGE_SIZE);
    expect(normaliseAuditPageSize(Number.NaN)).toBe(DEFAULT_AUDIT_PAGE_SIZE);
    expect(normaliseAuditPageSize(12.7)).toBe(12);
  });
});

describe("buildAuditEventPredicate", () => {
  it("always constrains the tenant", () => {
    const { text, params } = render(
      buildAuditEventPredicate({ tenantId: TENANT_ID }),
    );

    expect(text).toContain('"tenant_id"');
    expect(params).toEqual([TENANT_ID]);
  });

  it("adds each supplied filter and nothing else", () => {
    const filter: AuditEventFilter = {
      tenantId: TENANT_ID,
      endpointId: ENDPOINT_ID,
      actorType: "admin-user",
      actorId: "u1",
      targetType: "client",
      targetId: "app-1",
    };
    const { text, params } = render(buildAuditEventPredicate(filter));

    expect(text).toContain('"endpoint_id"');
    expect(text).toContain('"actor_type"');
    expect(text).toContain('"actor_id"');
    expect(text).toContain('"target_type"');
    expect(text).toContain('"target_id"');
    // The actor type is stored with the column's spelling, not the domain's.
    expect(params).toContain("admin_user");
    expect(params).not.toContain("admin-user");
  });

  it("uses an equality for one action and an IN list for several", () => {
    const single = render(
      buildAuditEventPredicate({
        tenantId: TENANT_ID,
        actions: ["token.issued"],
      }),
    );
    expect(single.text).not.toMatch(/\bin\b/i);
    expect(single.params).toContain("token.issued");

    const many = render(
      buildAuditEventPredicate({
        tenantId: TENANT_ID,
        actions: ["token.issued", "token.denied"],
      }),
    );
    expect(many.text).toMatch(/\bin\b/i);
    expect(many.params).toEqual([TENANT_ID, "token.issued", "token.denied"]);
  });

  it("treats an empty action list as no constraint", () => {
    const { params } = render(
      buildAuditEventPredicate({ tenantId: TENANT_ID, actions: [] }),
    );

    expect(params).toEqual([TENANT_ID]);
  });

  it("makes the time range half-open", () => {
    const from = new Date("2026-01-01T00:00:00.000Z");
    const until = new Date("2026-02-01T00:00:00.000Z");
    const { text } = render(
      buildAuditEventPredicate({ tenantId: TENANT_ID, from, until }),
    );

    expect(text).toContain(">=");
    expect(text).toContain("<");
    expect(text).not.toContain("<=");
  });

  it("pages by keyset row comparison rather than OFFSET", () => {
    const after = {
      at: new Date("2026-05-01T09:00:00.000Z"),
      id: "33333333-3333-4333-8333-333333333333",
    };
    const newest = render(
      buildAuditEventPredicate({ tenantId: TENANT_ID, after }),
    );

    expect(newest.text).not.toMatch(/offset/i);
    expect(newest.text).toContain("::timestamptz");
    expect(newest.text).toContain("::uuid");
    expect(newest.text).toContain("<");
    expect(newest.params).toContain("2026-05-01T09:00:00.000Z");
    expect(newest.params).toContain(after.id);

    const oldest = render(
      buildAuditEventPredicate({
        tenantId: TENANT_ID,
        after,
        order: "oldest-first",
      }),
    );
    expect(oldest.text).toContain(">");
  });
});

describe("toAuditEventRecord", () => {
  it("maps the stored spellings back onto the domain", () => {
    const record = toAuditEventRecord(
      aRow({ actorType: "end_user", detail: { reason: "bad-audience" } }),
    );

    expect(record.actorType).toBe("end-user");
    expect(record.action).toBe("endpoint.updated");
    expect(record.detail).toEqual({ reason: "bad-audience" });
    expect(record.at).toEqual(new Date("2026-05-01T09:00:00.000Z"));
  });

  it("keeps nulls as nulls", () => {
    const record = toAuditEventRecord(
      aRow({
        endpointId: null,
        actorId: null,
        targetType: null,
        targetId: null,
        ip: null,
        userAgent: null,
      }),
    );

    expect(record.endpointId).toBeNull();
    expect(record.actorId).toBeNull();
    expect(record.ip).toBeNull();
  });
});

describe("auditEventCursorOf", () => {
  it("takes both halves of the position", () => {
    const record = toAuditEventRecord(aRow());

    expect(auditEventCursorOf(record)).toEqual({
      at: record.at,
      id: record.id,
    });
  });
});

describe("queryAuditEvents", () => {
  /** Distinct rows, newest first, as the default ordering would return them. */
  function rows(count: number): AuditEvent[] {
    return Array.from({ length: count }, (_, index) =>
      aRow({
        id: `33333333-3333-4333-8333-${String(index).padStart(12, "0")}`,
        at: new Date(Date.UTC(2026, 4, 1, 9, 0, count - index)),
      }),
    );
  }

  it("asks for one row more than the page, to know whether there is another", async () => {
    const capture: SelectCapture = {};

    await queryAuditEvents(await selecting(rows(3), capture), {
      limit: 2,
    });

    expect(capture.limit).toBe(3);
  });

  it("returns a full page and a cursor onto the next one", async () => {
    const page = await queryAuditEvents(await selecting(rows(3), {}), {
      limit: 2,
    });

    expect(page.events).toHaveLength(2);
    expect(page.nextCursor).toEqual({
      at: page.events[1]?.at,
      id: page.events[1]?.id,
    });
  });

  it("reports the end of the trail with a null cursor", async () => {
    const page = await queryAuditEvents(await selecting(rows(2), {}), {
      limit: 5,
    });

    expect(page.events).toHaveLength(2);
    expect(page.nextCursor).toBeNull();
  });

  it("handles an empty trail", async () => {
    const page = await queryAuditEvents(await selecting([], {}), {});

    expect(page.events).toEqual([]);
    expect(page.nextCursor).toBeNull();
  });

  it("orders on both cursor columns, newest first by default", async () => {
    const capture: SelectCapture = {};

    await queryAuditEvents(await selecting(rows(1), capture), {});

    expect(capture.order).toHaveLength(2);
    expect(render(capture.order?.[0] as SQL).text).toContain("desc");
    expect(render(capture.order?.[1] as SQL).text).toContain("desc");
  });

  it("orders ascending when asked to read forwards", async () => {
    const capture: SelectCapture = {};

    await queryAuditEvents(await selecting(rows(1), capture), {
      order: "oldest-first",
    });

    expect(render(capture.order?.[0] as SQL).text).toContain("asc");
  });

  it("applies the filter it was given", async () => {
    const capture: SelectCapture = {};

    await queryAuditEvents(await selecting(rows(1), capture), {
      actions: ["token.revoked"],
    });

    expect(render(capture.predicate as SQL).params).toContain("token.revoked");
  });

  it("clamps an oversized page request", async () => {
    const capture: SelectCapture = {};

    await queryAuditEvents(await selecting([], capture), {
      limit: 10_000,
    });

    expect(capture.limit).toBe(MAX_AUDIT_PAGE_SIZE + 1);
  });
});
