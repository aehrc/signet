/**
 * The layout pieces every page is built from.
 *
 * These exist to keep Tailwind class combinations in one place. The project's React
 * guidelines are explicit about it: if two elements share a style, the style belongs
 * in a component. That is also what makes the daisyUI theme lock meaningful - every
 * colour here is a semantic token (`base-100`, `primary`, `error`), never a palette
 * value, so the whole product re-themes from one word in `styles.css`.
 *
 * Author: John Grimes
 */

import type { ReactNode } from "react";

interface PageHeaderProps {
  readonly title: string;
  /** One sentence saying what this page is for, or what it decides. */
  readonly description?: ReactNode;
  /** Buttons, aligned to the trailing edge. */
  readonly actions?: ReactNode;
}

/** The title block at the top of a page. */
export function PageHeader({
  title,
  description,
  actions,
}: Readonly<PageHeaderProps>) {
  return (
    <header className="mb-6 flex flex-wrap items-start justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {description === undefined ? null : (
          <p className="text-base-content/70 mt-1 max-w-2xl text-sm">
            {description}
          </p>
        )}
      </div>
      {actions === undefined ? null : (
        <div className="flex flex-wrap gap-2">{actions}</div>
      )}
    </header>
  );
}

interface PanelProps {
  readonly title?: string;
  readonly description?: ReactNode;
  readonly actions?: ReactNode;
  readonly children: ReactNode;
}

/** A titled card. The console's only container. */
export function Panel({
  title,
  description,
  actions,
  children,
}: Readonly<PanelProps>) {
  return (
    <section className="card bg-base-100 border-base-300 mb-6 border shadow-sm">
      <div className="card-body gap-4">
        {title === undefined && actions === undefined ? null : (
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              {title === undefined ? null : (
                <h2 className="card-title text-base">{title}</h2>
              )}
              {description === undefined ? null : (
                <p className="text-base-content/70 text-sm">{description}</p>
              )}
            </div>
            {actions === undefined ? null : (
              <div className="flex flex-wrap gap-2">{actions}</div>
            )}
          </div>
        )}
        {children}
      </div>
    </section>
  );
}

interface EmptyStateProps {
  readonly title: string;
  /** What this thing is, and why the reader might want one. */
  readonly description: ReactNode;
  readonly action?: ReactNode;
}

/**
 * What a list shows when it is empty.
 *
 * Always says what the missing thing *is*, rather than only that there is none of
 * it: an empty endpoint list is the first screen a new operator sees, and "no
 * endpoints" alone tells them nothing about what to do next.
 */
export function EmptyState({
  title,
  description,
  action,
}: Readonly<EmptyStateProps>) {
  return (
    <div className="border-base-300 rounded-box border border-dashed px-6 py-10 text-center">
      <p className="font-medium">{title}</p>
      <p className="text-base-content/70 mx-auto mt-2 max-w-md text-sm">
        {description}
      </p>
      {action === undefined ? null : <div className="mt-4">{action}</div>}
    </div>
  );
}

/** A short failure message, in the shape daisyUI gives an alert. */
export function ErrorAlert({
  message,
  children,
}: Readonly<{ readonly message: string; readonly children?: ReactNode }>) {
  return (
    <div role="alert" className="alert alert-error">
      <div>
        <p className="font-medium">{message}</p>
        {children}
      </div>
    </div>
  );
}

/** A brief note that something succeeded, or a caveat about what it did. */
export function InfoAlert({
  children,
}: Readonly<{ readonly children: ReactNode }>) {
  return (
    <div role="status" className="alert alert-info">
      <div>{children}</div>
    </div>
  );
}

/** The placeholder shown while a query is in flight. */
export function Loading({ label }: Readonly<{ readonly label?: string }>) {
  return (
    <div className="flex items-center gap-3 py-8" role="status">
      <span className="loading loading-spinner loading-md" />
      <span className="text-base-content/70 text-sm">
        {label ?? "Loading…"}
      </span>
    </div>
  );
}

/** One label-and-value pair, for a definition list of configuration. */
export function DetailRow({
  label,
  children,
}: Readonly<{ readonly label: string; readonly children: ReactNode }>) {
  return (
    <div className="border-base-300 grid gap-1 border-b py-2 last:border-b-0 sm:grid-cols-3">
      <dt className="text-base-content/70 text-sm">{label}</dt>
      <dd className="text-sm sm:col-span-2">{children}</dd>
    </div>
  );
}

/** The container for {@link DetailRow}s. */
export function DetailList({
  children,
}: Readonly<{ readonly children: ReactNode }>) {
  return <dl className="w-full">{children}</dl>;
}

/**
 * A value worth reading exactly, with a way to copy it.
 *
 * Issuers, JWKS URLs and client identifiers are all pasted into somebody else's
 * configuration, and a transcription error in any of them produces a failure that
 * looks like a Signet bug.
 */
export function CopyableValue({
  value,
  label,
}: Readonly<{ readonly value: string; readonly label?: string }>) {
  return (
    <div className="flex items-center gap-2">
      <code className="bg-base-200 rounded-field min-w-0 flex-1 overflow-x-auto px-2 py-1 font-mono text-xs">
        {value}
      </code>
      <button
        type="button"
        className="btn btn-ghost btn-xs"
        aria-label={label === undefined ? "Copy" : `Copy ${label}`}
        onClick={() => {
          void navigator.clipboard.writeText(value);
        }}
      >
        Copy
      </button>
    </div>
  );
}

/**
 * A credential the server will never show again.
 *
 * Visually distinct from an ordinary value, and says so in words: a client secret
 * or a personal access token exists in exactly one response, and an operator who
 * navigates away without copying it has to rotate rather than look it up.
 */
export function ShownOnce({
  title,
  value,
}: Readonly<{ readonly title: string; readonly value: string }>) {
  return (
    <div className="alert alert-warning items-start" role="status">
      <div className="min-w-0 flex-1">
        <p className="font-medium">{title}</p>
        <p className="mt-1 mb-2 text-sm">
          Copy it now. It is stored only as a hash, so this is the one time it
          can be read - a lost credential is rotated, not recovered.
        </p>
        <CopyableValue value={value} label={title} />
      </div>
    </div>
  );
}
