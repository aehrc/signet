/**
 * The audit browser.
 *
 * Reads one page at a time through the API's keyset cursor rather than an offset,
 * because `audit_events` only grows: paging by offset both costs more the further in
 * you go and shifts every subsequent page when a row is written between requests.
 * The cursor is opaque here, exactly as the API intends — the console holds it and
 * hands it back.
 *
 * The action filter is a free-text field rather than a select over every action.
 * There are around fifty, the names are stable and dotted (`token.issued`), and the
 * API refuses one it does not record — so typing is faster than hunting, and a
 * mistake is answered rather than silently matching nothing.
 */

import { useState } from "react";

import { useConsoleContext } from "./useConsole.js";
import { describeError } from "../api/errors.js";
import { useAudit, useEndpoints } from "../api/queries.js";
import { SelectField, TextField } from "../components/fields.js";
import {
  EmptyState,
  ErrorAlert,
  Loading,
  PageHeader,
  Panel,
} from "../components/layout.js";
import { DataTable } from "../components/table.js";
import { formatInstant, formatSince, truncate } from "../formatting/values.js";
import { parseList } from "../forms/lists.js";

import type { AuditQuery } from "../api/paths.js";
import type { AuditEventView } from "../api/types.js";
import type { Column } from "../components/table.js";

/** How many events a page holds. */
const PAGE_SIZE = 50;

/** The audit browser. */
export function AuditPage() {
  const { tenant } = useConsoleContext();
  const endpoints = useEndpoints(tenant);

  const [actions, setActions] = useState("");
  const [actorType, setActorType] = useState("");
  const [endpointSlug, setEndpointSlug] = useState("");
  const [from, setFrom] = useState("");
  // Every page visited, so paging back is instant and does not need a second
  // cursor direction from the API.
  const [cursors, setCursors] = useState<readonly (string | undefined)[]>([
    undefined,
  ]);
  const [pageIndex, setPageIndex] = useState(0);

  const query: AuditQuery = {
    limit: PAGE_SIZE,
    ...(endpointSlug.length === 0 ? {} : { endpointSlug }),
    ...(actorType.length === 0 ? {} : { actorType }),
    ...(actions.trim().length === 0 ? {} : { action: parseList(actions) }),
    ...(from.length === 0 ? {} : { from: new Date(from).toISOString() }),
    ...(cursors[pageIndex] === undefined ? {} : { cursor: cursors[pageIndex] }),
  };

  const page = useAudit(tenant, query);
  const now = new Date();

  /** Resets paging whenever a filter changes: page three of a new filter is not page three. */
  const changeFilter = (apply: () => void) => {
    apply();
    setCursors([undefined]);
    setPageIndex(0);
  };

  const columns: readonly Column<AuditEventView>[] = [
    {
      key: "at",
      header: "When",
      cell: (event) => (
        <span className="text-xs" title={formatInstant(event.at)}>
          {formatSince(event.at, now)}
        </span>
      ),
    },
    {
      key: "action",
      header: "Action",
      cell: (event) => (
        <div>
          <code className="font-mono text-xs">{event.action}</code>
          {event.description === null ? null : (
            <div className="text-base-content/60 text-xs">
              {event.description}
            </div>
          )}
        </div>
      ),
    },
    {
      key: "actor",
      header: "Actor",
      cell: (event) => (
        <div className="text-xs">
          <div>{event.actorType}</div>
          {event.actorId === null ? null : (
            <code className="text-base-content/60 font-mono">
              {truncate(
                typeof event.detail["actorDisplayName"] === "string"
                  ? event.detail["actorDisplayName"]
                  : event.actorId,
                28,
              )}
            </code>
          )}
        </div>
      ),
    },
    {
      key: "target",
      header: "Target",
      secondary: true,
      cell: (event) =>
        event.targetType === null ? (
          <span className="text-base-content/50">—</span>
        ) : (
          <div className="text-xs">
            <div>{event.targetType}</div>
            {event.targetId === null ? null : (
              <code className="text-base-content/60 font-mono">
                {truncate(event.targetId, 24)}
              </code>
            )}
          </div>
        ),
    },
    {
      key: "detail",
      header: "Detail",
      secondary: true,
      cell: (event) => <AuditDetail event={event} />,
    },
  ];

  return (
    <>
      <PageHeader
        title="Audit"
        description="Every authorization decision and every configuration change, append-only. Nothing in Signet updates or deletes an event."
      />

      <Panel title="Filter">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <SelectField
            label="Endpoint"
            value={endpointSlug}
            onChange={(value) => {
              changeFilter(() => setEndpointSlug(value));
            }}
            options={[
              { value: "", label: "All endpoints" },
              ...(endpoints.data ?? []).map((endpoint) => ({
                value: endpoint.slug,
                label: endpoint.name,
              })),
            ]}
          />
          <SelectField
            label="Actor"
            value={actorType}
            onChange={(value) => {
              changeFilter(() => setActorType(value));
            }}
            options={[
              { value: "", label: "Anyone" },
              { value: "admin-user", label: "Administrator" },
              { value: "api-token", label: "Personal access token" },
              { value: "end-user", label: "End user" },
              { value: "client", label: "Client" },
              { value: "system", label: "System" },
            ]}
          />
          <TextField
            label="Actions"
            value={actions}
            onChange={(value) => {
              changeFilter(() => setActions(value));
            }}
            hint="Dotted names, comma-separated. For example token.denied, authorize.denied."
          />
          <TextField
            label="Since"
            type="text"
            value={from}
            onChange={(value) => {
              changeFilter(() => setFrom(value));
            }}
            hint="A date, as 2026-08-01."
          />
        </div>
      </Panel>

      <Panel>
        {page.isPending ? <Loading /> : null}
        {page.isError ? (
          <ErrorAlert message={describeError(page.error)} />
        ) : null}
        {page.data === undefined ? null : (
          <>
            <DataTable
              columns={columns}
              rows={page.data.events}
              rowKey={(event) => event.id}
              empty={
                <EmptyState
                  title="No events match"
                  description="Either nothing has happened in this range, or the filter is narrower than you meant."
                />
              }
            />

            <div className="flex items-center justify-between gap-2">
              <span className="text-base-content/60 text-xs">
                Page {String(pageIndex + 1)}
              </span>
              <div className="join">
                <button
                  type="button"
                  className="btn btn-outline btn-sm join-item"
                  disabled={pageIndex === 0}
                  onClick={() => {
                    setPageIndex((index) => Math.max(0, index - 1));
                  }}
                >
                  Previous
                </button>
                <button
                  type="button"
                  className="btn btn-outline btn-sm join-item"
                  disabled={page.data.nextCursor === null}
                  onClick={() => {
                    const next = page.data.nextCursor;
                    if (next === null) {
                      return;
                    }
                    setCursors((visited) =>
                      visited.length === pageIndex + 1
                        ? [...visited, next]
                        : visited,
                    );
                    setPageIndex((index) => index + 1);
                  }}
                >
                  Next
                </button>
              </div>
            </div>
          </>
        )}
      </Panel>
    </>
  );
}

/**
 * An event's detail blob, rendered compactly.
 *
 * The keys the recorder adds for readability — the actor's display name, the
 * endpoint's slug — are dropped, because the surrounding columns already carry them
 * and repeating them fills the cell with what the reader can already see.
 */
function AuditDetail({ event }: Readonly<{ readonly event: AuditEventView }>) {
  const hidden = new Set(["actorDisplayName", "actorId", "endpointSlug"]);
  const entries = Object.entries(event.detail).filter(
    ([key]) => !hidden.has(key),
  );

  if (entries.length === 0) {
    return <span className="text-base-content/50">—</span>;
  }

  return (
    <div className="flex flex-col gap-0.5">
      {entries.map(([key, value]) => (
        <span key={key} className="font-mono text-xs">
          <span className="text-base-content/60">{key}</span>{" "}
          {truncate(
            typeof value === "string" ? value : JSON.stringify(value),
            36,
          )}
        </span>
      ))}
    </div>
  );
}
