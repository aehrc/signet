/**
 * The console's one table.
 *
 * Every list in the console is the same shape - columns, rows, a placeholder when
 * empty - and writing that out per page would be five copies of the same markup
 * with different padding. Columns are described as data so a page says what it
 * wants to show rather than how a `<td>` is styled.
 *
 * Describing them as data is also what makes the same list renderable two ways.
 * A table is the right shape for a wide screen and the wrong shape for a phone:
 * at 360px a four-column list either scrolls sideways inside itself, which puts
 * the status of every row off the edge, or squeezes each column to a few
 * characters. So below `sm` the same columns and rows are laid out as one card
 * per row - the first column as the card's title, every other column as a
 * labelled value underneath it - and the table is hidden. Both renderings are in
 * the markup at once and a breakpoint class decides which is on screen, so there
 * is no media-query hook, no resize subscription and no first paint in the wrong
 * shape. `hidden` is `display: none`, which also takes the hidden half out of the
 * accessibility tree, so a reader - or a test - looking for a link finds one of
 * them rather than two.
 *
 * The card calls the same `column.cell(row)` the table calls. That is not only to
 * keep the duplication detector at its zero threshold: two copies of a cell's
 * markup would be two things to change, and the phone would eventually show
 * something the desktop did not.
 *
 * ## The card's links are its controls
 *
 * A row's first column is almost always a link to the thing the row is about, and
 * on a card that link is usually the only way off the card. On a desktop it is a
 * pointer target inside a 700px row; at 360px it is the card's navigation, and an
 * anchor is 18px tall because an anchor is text. So every anchor in a card is
 * given a 44px box below `sm` - `inline-flex` first, because `min-height` does
 * nothing to an inline box, and `items-center` so the text sits in the middle of
 * the box rather than at the top of it.
 *
 * Applied here rather than at each list for the same reason `ACTION_ROW` and the
 * drawer's entries are: the links are a caller's children, eight pages render
 * through this component, and a rule per page is a rule somebody forgets. It also
 * reaches the per-row action links, which FR-006 keeps on the card.
 *
 * Author: John Grimes
 */

import type { BadgeTone } from "../formatting/status.js";
import type { ReactNode } from "react";

/** One column of a {@link DataTable}. */
export interface Column<Row> {
  /** Stable key, also used as the React key for the cell. */
  readonly key: string;
  /** The column heading, reused as the value's label in the mobile card. */
  readonly header: ReactNode;
  /** Renders the cell. Given the whole row, so a cell may combine fields. */
  readonly cell: (row: Row) => ReactNode;
}

interface DataTableProps<Row> {
  readonly columns: readonly Column<Row>[];
  readonly rows: readonly Row[];
  /** Distinguishes rows for React, and for the `key` on each `<tr>`. */
  readonly rowKey: (row: Row) => string;
  /** Shown instead of the table when there are no rows. */
  readonly empty: ReactNode;
  /** Applied to a row's `<tr>` and to its card; marks a row as inactive. */
  readonly rowClassName?: (row: Row) => string | undefined;
}

/** A list of rows, or the empty state when there are none. */
export function DataTable<Row>({
  columns,
  rows,
  rowKey,
  empty,
  rowClassName,
}: Readonly<DataTableProps<Row>>) {
  if (rows.length === 0) {
    return <>{empty}</>;
  }

  const [title, ...rest] = columns;

  return (
    <>
      <div className="hidden overflow-x-auto sm:block">
        <table className="table-zebra table w-full text-sm">
          <thead>
            <tr>
              {columns.map((column) => (
                <th key={column.key}>{column.header}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={rowKey(row)} className={rowClassName?.(row)}>
                {columns.map((column) => (
                  <td key={column.key}>{column.cell(row)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <ul className="flex list-none flex-col gap-3 sm:hidden">
        {rows.map((row) => (
          <li
            key={rowKey(row)}
            className={`border-base-300 rounded-box min-w-0 border p-4 max-sm:[&_a]:inline-flex max-sm:[&_a]:min-h-11 max-sm:[&_a]:min-w-11 max-sm:[&_a]:items-center max-sm:[&_.btn]:min-h-11 ${rowClassName?.(row) ?? ""}`}
          >
            <div className="min-w-0 font-medium break-words">
              {title === undefined ? null : title.cell(row)}
            </div>
            <dl className="mt-1 flex flex-col">
              {rest.map((column) => {
                const value = column.cell(row);
                // A cell that renders nothing gets no row: the actions column
                // is empty for a row with no action left to take, and a labelled
                // blank with a rule above it reads as a rendering fault.
                return value === null || value === undefined ? null : (
                  <div
                    key={column.key}
                    className="border-base-300 flex flex-wrap items-start justify-between gap-x-4 gap-y-1 border-t pt-2 pb-1 first:mt-2"
                  >
                    <dt className="text-base-content/60 text-xs tracking-wide uppercase">
                      {column.header}
                    </dt>
                    <dd className="min-w-0 text-right break-words">{value}</dd>
                  </div>
                );
              })}
            </dl>
          </li>
        ))}
      </ul>
    </>
  );
}

/** daisyUI's class for each tone, so no page picks one by hand. */
const TONE_CLASSES: Readonly<Record<BadgeTone, string>> = {
  neutral: "badge-neutral",
  success: "badge-success",
  warning: "badge-warning",
  error: "badge-error",
  info: "badge-info",
};

/** A short status word, coloured by tone. */
export function StatusBadge({
  children,
  tone = "neutral",
}: Readonly<{ readonly children: ReactNode; readonly tone?: BadgeTone }>) {
  return (
    <span className={`badge badge-sm ${TONE_CLASSES[tone]}`}>{children}</span>
  );
}

/**
 * A list of short values, wrapped rather than truncated.
 *
 * "Short" is what a scope is and what a redirect URI is not. The container wraps
 * from one chip to the next, which is enough for a list of scopes and nothing at
 * all for a list of one 2048-character redirect URI: a URI has no space in it, so
 * a single chip with no internal break point is one word as wide as the value, and
 * a flex item's automatic minimum size is its longest word. It widens the page on
 * its own.
 *
 * So each chip breaks inside itself, with `break-all` rather than the `break-words`
 * used for prose elsewhere: a chip holds a URI in a monospace face, where breaking
 * between any two characters fills the line better than breaking only where a whole
 * word will not fit. That also takes the chip's minimum size down to one character,
 * which is what lets the flex item shrink.
 */
export function Chips({
  values,
}: Readonly<{ readonly values: readonly string[] }>) {
  if (values.length === 0) {
    return <span className="text-base-content/50">none</span>;
  }
  return (
    <span className="flex flex-wrap gap-1">
      {values.map((value) => (
        <code
          key={value}
          className="bg-base-200 rounded-field px-1.5 py-0.5 font-mono text-xs break-all"
        >
          {value}
        </code>
      ))}
    </span>
  );
}
