/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The table's two renderings, asserted from server-rendered markup.
 *
 * A console list is a table on a desktop and a stack of labelled cards on a
 * phone, and both are in the markup at once - which of them a reader sees is
 * decided by a breakpoint class, not by a media-query hook. That makes the
 * switch assertable here, from static markup, in both directions: the table
 * carries `hidden sm:block` and the card list carries `sm:hidden`, so a
 * rendering that stopped hiding one of them would be caught without a browser.
 *
 * These are class assertions rather than measured layout, for the same reason as
 * the other component tests in this directory: static markup has no layout. That
 * the browser then honours the classes - cards at 360px, the table at desktop
 * width - is measured by `e2e/tests/responsive.spec.ts` and by the existing
 * desktop suite's table assertions.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

import { Chips, DataTable } from "./table.js";

import type { Column } from "./table.js";

/** A row of the fixture list below. */
interface Client {
  readonly clientId: string;
  readonly name: string;
  readonly redirectUri: string;
  readonly status: string;
}

/** Two clients, one of them disabled so `rowClassName` has something to mark. */
const CLIENTS: readonly Client[] = [
  {
    clientId: "cardiac-risk",
    name: "Cardiac Risk Calculator",
    redirectUri: "https://cardiac.example.org/callback",
    status: "active",
  },
  {
    clientId: "bulk-analytics",
    name: "Bulk Analytics Service",
    redirectUri: "https://analytics.example.org/callback",
    status: "disabled",
  },
];

/** The columns those clients are shown through. */
const COLUMNS: readonly Column<Client>[] = [
  { key: "name", header: "Client", cell: (client) => client.name },
  {
    key: "redirect",
    header: "Redirect URI",
    cell: (client) => <code>{client.redirectUri}</code>,
  },
  { key: "status", header: "Status", cell: (client) => client.status },
  {
    key: "actions",
    header: "",
    // Nothing to revoke on a client that is already disabled, which is how the
    // console's own action columns behave.
    cell: (client) =>
      client.status === "active" ? (
        <button type="button">Revoke {client.clientId}</button>
      ) : null,
  },
];

/** The rendering every assertion below reads, so it is built once. */
const markup = renderToStaticMarkup(
  <DataTable
    columns={COLUMNS}
    rows={CLIENTS}
    rowKey={(client) => client.clientId}
    rowClassName={(client) =>
      client.status === "active" ? undefined : "opacity-60"
    }
    empty={<p>No clients registered</p>}
  />,
);

describe("DataTable at and above sm", () => {
  it("keeps the table, and hides it below sm", () => {
    // Both halves matter. Without `hidden` the table would still be on screen at
    // 360px, which is the defect; without `sm:block` the desktop would lose the
    // table altogether, which is SC-006.
    expect(markup).toContain("hidden overflow-x-auto sm:block");
  });

  it("renders every column as a table cell, none of them hidden", () => {
    // `secondary` hid a column below `sm` - exactly where the table is no longer
    // what renders - so the flag has nothing left to do and the class it emitted
    // must be gone with it (FR-005).
    expect(markup).not.toContain("hidden sm:table-cell");
    expect(markup).toContain("<th>Client</th>");
    expect(markup).toContain("<th>Redirect URI</th>");
    expect(markup).toContain("<th>Status</th>");
  });
});

describe("DataTable below sm", () => {
  it("renders a card list, and hides it at sm and above", () => {
    expect(markup).toContain("sm:hidden");
  });

  it("titles each card with the first column's cell", () => {
    expect(markup).toContain("Cardiac Risk Calculator");
    expect(markup).toContain("Bulk Analytics Service");
  });

  it("labels every remaining column with its header", () => {
    // The label is `column.header`, reused rather than a second piece of column
    // metadata: the headers are already the human-readable name of the value.
    expect(markup).toContain("<dt");
    expect(markup).toContain(">Redirect URI</dt>");
    expect(markup).toContain(">Status</dt>");
  });

  it("does not repeat the title column as a labelled value", () => {
    // "Client" is the card's title, so a `Client:` row under it would say the
    // same thing twice.
    expect(markup).not.toContain(">Client</dt>");
  });

  it("shows every column, including ones the desktop table used to hide", () => {
    // FR-005 and SC-003: a card shows everything, so no value is unreachable on
    // a phone. Counting the cards' own values rather than the table's, because
    // the table has the same text in it.
    const cardValues = markup.match(/<dd/g) ?? [];
    // Three non-title columns over two rows, less the one action cell that has
    // nothing to render for the disabled client.
    expect(cardValues.length).toBe(5);
  });

  it("leaves out a row whose cell renders nothing", () => {
    // The disabled client has no action, and a labelled blank under a rule reads
    // as a rendering fault rather than as an absence.
    // The last occurrence, which is the card: the table above it holds the same
    // name, and the card list is what this is about.
    const disabled = markup.slice(markup.lastIndexOf("Bulk Analytics Service"));
    expect(disabled).not.toContain("Revoke");
    expect((disabled.match(/<dd/g) ?? []).length).toBe(2);
  });

  it("keeps a row's per-row action operable in its card", () => {
    // FR-006. The cell is rendered by the same `column.cell(row)` call the table
    // makes, so the two presentations cannot disagree about what a row offers.
    const revokes = markup.match(/Revoke cardiac-risk/g) ?? [];
    expect(revokes.length).toBe(2);
  });

  it("lets a long value break rather than widening the card", () => {
    // A redirect URI is one word with nothing in it to break at, and one of them
    // is what makes a 360px page scroll sideways.
    expect(markup).toContain("break-words");
  });

  it("carries the row marking to the card", () => {
    // The disabled client is dimmed in the table; a reader on a phone has to be
    // able to see the same thing.
    const dimmed = markup.match(/opacity-60/g) ?? [];
    expect(dimmed.length).toBe(2);
  });
});

describe("DataTable with no rows", () => {
  const emptyMarkup = renderToStaticMarkup(
    <DataTable
      columns={COLUMNS}
      rows={[]}
      rowKey={(client) => client.clientId}
      empty={<p>No clients registered</p>}
    />,
  );

  it("renders the placeholder instead of either rendering", () => {
    expect(emptyMarkup).toBe("<p>No clients registered</p>");
  });
});

describe("Chips", () => {
  /** One redirect URI of 129 characters, which is a legal one. */
  const LONG_URI =
    "https://immunisation-registry.population-health-programmes.example.org" +
    "/oauth2/callback/production-deployment-a/response";

  it("gives a single long chip somewhere to break inside itself", () => {
    // The container wraps from one chip to the next, which does nothing for a
    // list of one: a URI has no space in it, so without an internal break point
    // the chip is as wide as the value and widens the page with it. Measured in
    // a browser by `e2e/tests/responsive.spec.ts`; asserted here because the
    // component has eight call sites and each of them inherits this.
    const markup = renderToStaticMarkup(<Chips values={[LONG_URI]} />);
    expect(markup).toContain("break-all");
    expect(markup).toContain(LONG_URI);
  });

  it("says so when there is nothing to list", () => {
    expect(renderToStaticMarkup(<Chips values={[]} />)).toContain("none");
  });
});

describe("Column", () => {
  it("no longer offers a secondary flag", () => {
    const column: Column<Client> = {
      key: "status",
      header: "Status",
      cell: (client) => client.status,
      // @ts-expect-error - `secondary` was removed with the card list: its only
      // effect was below `sm`, where the table is no longer what renders.
      secondary: true,
    };
    expect(column.key).toBe("status");
  });
});
