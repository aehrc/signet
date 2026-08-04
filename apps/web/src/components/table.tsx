/**
 * The console's one table.
 *
 * Every list in the console is the same shape - columns, rows, a placeholder when
 * empty - and writing that out per page would be five copies of the same markup
 * with different padding. Columns are described as data so a page says what it
 * wants to show rather than how a `<td>` is styled.
 *
 * Author: John Grimes
 */

import type { BadgeTone } from "../formatting/status.js";
import type { ReactNode } from "react";

/** One column of a {@link DataTable}. */
export interface Column<Row> {
  /** Stable key, also used as the React key for the cell. */
  readonly key: string;
  readonly header: ReactNode;
  /** Renders the cell. Given the whole row, so a cell may combine fields. */
  readonly cell: (row: Row) => ReactNode;
  /** Hides the column below the `sm` breakpoint, for secondary detail. */
  readonly secondary?: boolean;
}

interface DataTableProps<Row> {
  readonly columns: readonly Column<Row>[];
  readonly rows: readonly Row[];
  /** Distinguishes rows for React, and for the `key` on each `<tr>`. */
  readonly rowKey: (row: Row) => string;
  /** Shown instead of the table when there are no rows. */
  readonly empty: ReactNode;
  /** Applied to a row's `<tr>`; used to mark a row as inactive. */
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

  return (
    <div className="overflow-x-auto">
      <table className="table-zebra table w-full text-sm">
        <thead>
          <tr>
            {columns.map((column) => (
              <th
                key={column.key}
                className={
                  column.secondary === true ? "hidden sm:table-cell" : ""
                }
              >
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={rowKey(row)} className={rowClassName?.(row)}>
              {columns.map((column) => (
                <td
                  key={column.key}
                  className={
                    column.secondary === true ? "hidden sm:table-cell" : ""
                  }
                >
                  {column.cell(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
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

/** A list of short values, wrapped rather than truncated. */
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
          className="bg-base-200 rounded-field px-1.5 py-0.5 font-mono text-xs"
        >
          {value}
        </code>
      ))}
    </span>
  );
}
