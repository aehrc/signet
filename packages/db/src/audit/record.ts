/**
 * Writing to and reading from the append-only audit log.
 *
 * Two deliberate asymmetries shape this module.
 *
 * The first is that there is no unredacted write path. `recordAuditEvent` is the
 * only exported function that inserts, and it runs every detail blob through
 * `redactAuditDetail` before it builds a row. The row builder is exported so it
 * can be tested without a database, but it redacts too, so a caller who reaches
 * for it still cannot smuggle a credential into the table.
 *
 * The second is that recording an event must never fail the operation being
 * audited - see {@link recordAuditEvent} for the trade-off and the risk it
 * accepts.
 *
 * Author: John Grimes
 */

import { and, asc, desc, eq, gte, inArray, lt, sql } from "drizzle-orm";

import {
  AUDIT_ACTOR_TYPE_FROM_COLUMN,
  AUDIT_ACTOR_TYPE_TO_COLUMN,
  type AuditAction,
  type AuditActorType,
  type AuditEventInput,
  type AuditEventRecord,
  type AuditTargetType,
} from "./events.js";
import { redactAuditDetail, redactAuditText } from "./redact.js";
import {
  auditEvents,
  type AuditEvent,
  type NewAuditEvent,
} from "../schema/audit.js";

import type { Executor } from "../repositories/executor.js";
import type { SQL } from "drizzle-orm";

/**
 * Detail keys the writer owns.
 *
 * These are set after redaction and overwrite whatever the call site put there,
 * so that the two fields a reader needs in order to make sense of a row whose
 * referents have since been deleted cannot be shadowed by a spread request body.
 */
export const AUDIT_DETAIL_RESERVED_KEYS = {
  /** The actor's name as it stood when the event happened. */
  actorDisplayName: "actorDisplayName",
  /** The endpoint's slug as it stood when the event happened. */
  endpointSlug: "endpointSlug",
} as const;

/**
 * Characters kept from a user agent string.
 *
 * The value is attacker-controlled and arrives on every request, so it is capped
 * far more tightly than a detail blob: no real user agent is this long, and an
 * append-only table is the wrong place to let a client choose the row size.
 */
const MAX_USER_AGENT_LENGTH = 512;

/** Characters kept from a client address. Comfortably fits IPv6 plus a port. */
const MAX_IP_LENGTH = 64;

/** Rows returned when the caller does not say. */
export const DEFAULT_AUDIT_PAGE_SIZE = 50;

/** Most rows one query will return, whatever the caller asks for. */
export const MAX_AUDIT_PAGE_SIZE = 200;

/**
 * A failed insert, in a form that is safe to log.
 *
 * It carries the *redacted* row rather than the original input, because a
 * failure reporter is by definition something that writes to a less controlled
 * place than the audit table - a log aggregator, an error tracker - and handing
 * it the raw detail blob would defeat the redactor for exactly the events that
 * are most likely to be interesting.
 */
export interface AuditRecordFailure {
  /** The action that could not be recorded. */
  readonly action: AuditAction;
  /** The tenant whose trail is now missing an event. */
  readonly tenantId: string;
  /** The row as it would have been inserted, already redacted. */
  readonly row: NewAuditEvent;
  /** Whatever the driver threw. */
  readonly error: unknown;
}

/** Somewhere to send an audit write that did not land. */
export type AuditFailureReporter = (failure: AuditRecordFailure) => void;

/**
 * Fallback reporter, used when the caller injects none.
 *
 * `console.error` is the one sink a library can assume exists. Production wires
 * its own reporter - a lost audit event should page someone.
 *
 * @param failure - The insert that failed.
 */
function reportToConsole(failure: AuditRecordFailure): void {
  console.error(
    `[signet] failed to record audit event ${failure.action} for tenant ${failure.tenantId}`,
    failure.error,
  );
}

/**
 * Clamps a header-derived string to a fixed length.
 *
 * @param value - Raw value, or undefined when the request did not carry one.
 * @param maxLength - Characters to keep.
 */
function clampHeader(
  value: string | undefined,
  maxLength: number,
): string | null {
  if (value === undefined) {
    return null;
  }
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return null;
  }
  return trimmed.length > maxLength ? trimmed.slice(0, maxLength) : trimmed;
}

/**
 * Builds the detail blob that will be persisted.
 *
 * @param event - The event as the call site described it.
 */
function buildDetail(event: AuditEventInput): Record<string, unknown> {
  const detail = redactAuditDetail(event.detail);

  const { displayName } = event.actor;
  if (displayName !== undefined) {
    detail[AUDIT_DETAIL_RESERVED_KEYS.actorDisplayName] =
      redactAuditText(displayName);
  }
  if (event.endpointSlug !== undefined) {
    detail[AUDIT_DETAIL_RESERVED_KEYS.endpointSlug] = redactAuditText(
      event.endpointSlug,
    );
  }

  return detail;
}

/**
 * Turns an event into the row that will be inserted.
 *
 * Pure, and exported so that redaction, the reserved detail keys and the header
 * caps can all be asserted without a database. It redacts unconditionally: this
 * being the only way to construct a row is what makes an unredacted write
 * impossible rather than merely discouraged.
 *
 * `at` is omitted when the caller did not supply one, so that Postgres stamps
 * the row from a single clock. That matters for more than tidiness: keyset
 * pagination orders on `at`, and a fleet of processes with drifting clocks would
 * interleave pages.
 *
 * @param event - The event to record.
 * @returns Insert values with a credential-free detail blob.
 */
export function buildAuditEventRow(event: AuditEventInput): NewAuditEvent {
  return {
    tenantId: event.tenantId,
    endpointId: event.endpointId ?? null,
    actorType: AUDIT_ACTOR_TYPE_TO_COLUMN[event.actor.type],
    actorId: event.actor.id ?? null,
    action: event.action,
    targetType: event.target?.type ?? null,
    targetId: event.target?.id ?? null,
    detail: buildDetail(event),
    ip: clampHeader(event.ip, MAX_IP_LENGTH),
    userAgent: clampHeader(event.userAgent, MAX_USER_AGENT_LENGTH),
    ...(event.at === undefined ? {} : { at: event.at }),
  };
}

/**
 * Records one event, swallowing any failure to do so.
 *
 * **The trade-off.** An audit write that throws must not turn a successful
 * authorization into a 500, nor a rejected one into a retryable error: the caller
 * has already decided, and often already acted. So a failed insert is reported
 * through `reportFailure` and the promise resolves normally.
 *
 * **The accepted risk.** Signet therefore cannot claim its audit log is complete
 * in the face of a database fault - an event can be lost while the operation it
 * describes succeeds, and nothing in the row set reveals the gap. That is
 * accepted deliberately, on the grounds that the alternative (failing the
 * operation) converts an audit outage into an availability outage for the whole
 * authorization server, and denial of service is the more likely attack.
 * Deployments that need the stronger guarantee must alert on the reporter, which
 * is why it is injectable and why nothing here defaults to silence.
 *
 * **Transactions.** Passing a transaction as `db` enlists the event in it, so an
 * event describing work that later rolls back rolls back too. That is usually
 * what you want for configuration changes. It is *not* what you want for a
 * refusal: audit a rejected credential on the connection, not inside the
 * transaction that is about to abort.
 *
 * @param db - Connection or transaction to insert through.
 * @param event - The event to record. Its detail blob is redacted first.
 * @param reportFailure - Where to send a failed insert. Defaults to
 *   `console.error`.
 */
export async function recordAuditEvent(
  db: Executor,
  event: AuditEventInput,
  reportFailure: AuditFailureReporter = reportToConsole,
): Promise<void> {
  const row = buildAuditEventRow(event);

  try {
    await db.insert(auditEvents).values(row);
  } catch (error) {
    try {
      reportFailure({
        action: event.action,
        tenantId: event.tenantId,
        row,
        error,
      });
    } catch {
      // A reporter that throws must not achieve what the database fault could
      // not. There is nowhere left to escalate to, so this is where it stops.
    }
  }
}

/**
 * A recorder with its failure reporter already bound.
 *
 * The server builds one at startup so that no call site has to remember to pass
 * the reporter, and so that forgetting cannot silently fall back to
 * `console.error`.
 */
export interface AuditRecorder {
  /**
   * Records one event.
   *
   * @param db - Connection or transaction to insert through.
   * @param event - The event to record.
   */
  record(db: Executor, event: AuditEventInput): Promise<void>;
}

/**
 * Binds a failure reporter to a recorder.
 *
 * @param reportFailure - Where to send a failed insert.
 */
export function createAuditRecorder(
  reportFailure: AuditFailureReporter,
): AuditRecorder {
  return {
    record: (db, event) => recordAuditEvent(db, event, reportFailure),
  };
}

/**
 * Position in a result set, for keyset pagination.
 *
 * `at` alone is not a position: events are written in bursts and a timestamp can
 * repeat, so a cursor on time alone would either skip or duplicate rows at a page
 * boundary. The identifier breaks the tie.
 */
export interface AuditEventCursor {
  /** Occurrence time of the last row on the previous page. */
  readonly at: Date;
  /** Identifier of the last row on the previous page. */
  readonly id: string;
}

/** Which end of the trail to read from. */
export type AuditEventOrder = "newest-first" | "oldest-first";

/** What to select from the audit log. */
export interface AuditEventFilter {
  /**
   * Tenant whose trail to read. Required, and applied first: there is no way to
   * ask this module for a cross-tenant page.
   */
  readonly tenantId: string;
  /** Restrict to one endpoint. */
  readonly endpointId?: string;
  /** Restrict to one kind of principal. */
  readonly actorType?: AuditActorType;
  /** Restrict to one principal. Pair with `actorType` to use the index. */
  readonly actorId?: string;
  /**
   * Restrict to these actions. An empty array is treated as no constraint,
   * matching a multi-select in which nothing is selected.
   */
  readonly actions?: readonly AuditAction[];
  /** Restrict to one kind of target. */
  readonly targetType?: AuditTargetType;
  /** Restrict to one target. Pair with `targetType` to use the index. */
  readonly targetId?: string;
  /** Earliest occurrence time to include, inclusive. */
  readonly from?: Date;
  /**
   * Latest occurrence time to include, exclusive.
   *
   * Half-open so that a caller paging by day can use midnight as both the end of
   * one range and the start of the next without double-counting.
   */
  readonly until?: Date;
  /** Rows to return, clamped to {@link MAX_AUDIT_PAGE_SIZE}. */
  readonly limit?: number;
  /** Read from just past this position. Omit for the first page. */
  readonly after?: AuditEventCursor;
  /** Defaults to newest first, which is what the audit browser opens on. */
  readonly order?: AuditEventOrder;
}

/** One page of audit events. */
export interface AuditEventPage {
  /** The rows, in the requested order. */
  readonly events: readonly AuditEventRecord[];
  /**
   * Position to pass as `after` for the next page, or null when this page is the
   * end of the trail.
   */
  readonly nextCursor: AuditEventCursor | null;
}

/**
 * Clamps a requested page size into the permitted range.
 *
 * A caller asking for zero or a negative number gets the default rather than an
 * error: this is a paging parameter that arrives from a query string, and an
 * audit browser should not 400 because someone edited the URL.
 *
 * @param limit - Requested page size, if any.
 */
export function normaliseAuditPageSize(limit: number | undefined): number {
  if (limit === undefined || !Number.isFinite(limit) || limit < 1) {
    return DEFAULT_AUDIT_PAGE_SIZE;
  }
  return Math.min(Math.floor(limit), MAX_AUDIT_PAGE_SIZE);
}

/**
 * Builds the keyset predicate for one direction of travel.
 *
 * Written as a row-value comparison rather than
 * `at < x OR (at = x AND id < y)` because Postgres can drive an index scan
 * straight from the former, which is the whole reason for preferring keyset
 * pagination over `OFFSET` on a table that only grows.
 *
 * @param cursor - Position to read past.
 * @param order - Direction the result set is ordered in.
 */
function cursorPredicate(
  cursor: AuditEventCursor,
  order: AuditEventOrder,
): SQL {
  const at = cursor.at.toISOString();
  return order === "newest-first"
    ? sql`(${auditEvents.at}, ${auditEvents.id}) < (${at}::timestamptz, ${cursor.id}::uuid)`
    : sql`(${auditEvents.at}, ${auditEvents.id}) > (${at}::timestamptz, ${cursor.id}::uuid)`;
}

/**
 * Turns a filter into a single SQL predicate.
 *
 * Pure, and exported so that the translation can be asserted against generated
 * SQL with no database - including the property that matters most, which is that
 * the tenant predicate is always present.
 *
 * @param filter - What to select.
 * @returns A conjunction that always includes the tenant predicate.
 */
export function buildAuditEventPredicate(filter: AuditEventFilter): SQL {
  // The tenant predicate is held separately from the optional ones so that it is
  // structurally impossible for a query to lose it - the type system, not a
  // comment, guarantees the conjunction is tenant-scoped and non-empty.
  const tenantPredicate: SQL = eq(auditEvents.tenantId, filter.tenantId);
  const conditions: SQL[] = [];

  if (filter.endpointId !== undefined) {
    conditions.push(eq(auditEvents.endpointId, filter.endpointId));
  }
  if (filter.actorType !== undefined) {
    conditions.push(
      eq(auditEvents.actorType, AUDIT_ACTOR_TYPE_TO_COLUMN[filter.actorType]),
    );
  }
  if (filter.actorId !== undefined) {
    conditions.push(eq(auditEvents.actorId, filter.actorId));
  }
  if (filter.actions !== undefined && filter.actions.length > 0) {
    const [only] = filter.actions;
    // A single action becomes an equality rather than a one-element `IN`, which
    // is the same plan but a far more readable statement in a slow-query log.
    conditions.push(
      filter.actions.length === 1 && only !== undefined
        ? eq(auditEvents.action, only)
        : inArray(auditEvents.action, [...filter.actions]),
    );
  }
  if (filter.targetType !== undefined) {
    conditions.push(eq(auditEvents.targetType, filter.targetType));
  }
  if (filter.targetId !== undefined) {
    conditions.push(eq(auditEvents.targetId, filter.targetId));
  }
  if (filter.from !== undefined) {
    conditions.push(gte(auditEvents.at, filter.from));
  }
  if (filter.until !== undefined) {
    conditions.push(lt(auditEvents.at, filter.until));
  }
  if (filter.after !== undefined) {
    conditions.push(
      cursorPredicate(filter.after, filter.order ?? "newest-first"),
    );
  }

  let combined: SQL = tenantPredicate;
  for (const condition of conditions) {
    // `and()` returns undefined only for an empty argument list, which cannot
    // happen here; the fallback keeps the type honest without a cast.
    combined = and(combined, condition) ?? combined;
  }
  return combined;
}

/**
 * Maps a stored row onto the domain shape.
 *
 * @param row - Row as selected.
 */
export function toAuditEventRecord(row: AuditEvent): AuditEventRecord {
  return {
    id: row.id,
    tenantId: row.tenantId,
    endpointId: row.endpointId,
    actorType: AUDIT_ACTOR_TYPE_FROM_COLUMN[row.actorType],
    actorId: row.actorId,
    // `action` is a text column and this is the only place the widening is
    // undone. Asserted rather than checked because `recordAuditEvent` is the
    // only writer and accepts nothing outside the union; a row written by a
    // newer deployment during a rolling upgrade will fail `isAuditAction`, which
    // is what a renderer should call before looking the value up.
    action: row.action as AuditAction,
    targetType: row.targetType,
    targetId: row.targetId,
    detail: row.detail,
    ip: row.ip,
    userAgent: row.userAgent,
    at: row.at,
  };
}

/**
 * Reads the cursor position of a row.
 *
 * @param record - Row to take a position from.
 */
export function auditEventCursorOf(record: AuditEventRecord): AuditEventCursor {
  return { at: record.at, id: record.id };
}

/**
 * Reads one page of the audit log.
 *
 * Fetches one row more than asked for, so that `nextCursor` reflects whether
 * there is genuinely more to read rather than guessing from a full page. The
 * extra row is discarded.
 *
 * @param db - Connection or transaction to read through.
 * @param filter - What to select and where to resume from.
 */
export async function queryAuditEvents(
  db: Executor,
  filter: AuditEventFilter,
): Promise<AuditEventPage> {
  const pageSize = normaliseAuditPageSize(filter.limit);
  const order = filter.order ?? "newest-first";
  const direction = order === "newest-first" ? desc : asc;

  const rows = await db
    .select()
    .from(auditEvents)
    .where(buildAuditEventPredicate(filter))
    .orderBy(direction(auditEvents.at), direction(auditEvents.id))
    .limit(pageSize + 1);

  const hasMore = rows.length > pageSize;
  const events = (hasMore ? rows.slice(0, pageSize) : rows).map(
    toAuditEventRecord,
  );
  const last = events.at(-1);

  return {
    events,
    nextCursor: hasMore && last !== undefined ? auditEventCursorOf(last) : null,
  };
}
