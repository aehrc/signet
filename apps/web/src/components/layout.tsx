/**
 * The layout pieces every page is built from.
 *
 * These exist to keep Tailwind class combinations in one place. The project's React
 * guidelines are explicit about it: if two elements share a style, the style belongs
 * in a component. That is also what makes the daisyUI theme lock meaningful - every
 * colour here is a semantic token (`base-100`, `primary`, `error`), never a palette
 * value, so the whole product re-themes from one word in `styles.css`.
 *
 * ## The 16px floor below `sm`
 *
 * FR-004 asks that text read at no less than 16 CSS pixels on a phone, and the
 * reading applied across this product is written down here because this is where
 * most of its prose is sized. The floor covers three things:
 *
 * 1. **Form controls** - what the reader types into or chooses from (`input`,
 *    `select`, `textarea`), and the buttons they press. The first is the
 *    requirement's own stated purpose: a mobile browser zooms a focused field
 *    under 16px and does not zoom back out. The controls are sized in
 *    `fields.js`; the buttons are sized here, through the same descendant
 *    selectors that give them their 44px targets, because daisyUI puts them at
 *    14px, 12px and 11px for `btn`, `btn-sm` and `btn-xs`.
 * 2. **The inherited body size.** daisyUI's `card-body` sets a font size of its
 *    own (`--card-fs`, 0.875rem), so text inside a panel that asks for no size
 *    renders at 14px however the page is written. Below `sm` that property is put
 *    back to 1rem, here and in `CentredShell`.
 * 3. **Running prose addressed to the reader** - page and panel descriptions,
 *    shell subtitles, empty-state copy, field hints, validation and status
 *    messages. Each carries `max-sm:text-base` beside its desktop `text-sm` or
 *    `text-xs`, so the denser desktop rendering is untouched (SC-006).
 *
 * It deliberately does **not** cover the annotation layer: the uppercase field
 * labels and the values inside a mobile card, badges, timestamps, monospace
 * identifiers, code and diff text, and the tab strips. Those are read as marks
 * against a value rather than as text, and `wireframes/mobile-card-list.html` -
 * the approved design - fixes them at 0.7rem and 0.85rem while putting its
 * buttons at 0.95rem. Raising the annotations would change that design rather
 * than implement it, and would cost the density that makes a card list legible
 * at 360px in the first place.
 *
 * Wrapping is the other thing kept in one place. Almost every long value in this
 * product - an issuer, a JWKS URL, a client identifier, a key thumbprint - is one
 * word with nothing in it to break at, and a page that scrolls sideways on a phone
 * usually has exactly one of those in it. Two classes are needed rather than one:
 * `break-words` gives the word somewhere to break, and `min-w-0` removes the
 * automatic minimum size that would otherwise stop the flex or grid item shrinking
 * far enough for the break to be reached.
 *
 * Author: John Grimes
 */

import {
  AlertIcon,
  CheckIcon,
  CopyIcon,
  InboxIcon,
  InfoIcon,
  XCircleIcon,
} from "@primer/octicons-react";
import { useState } from "react";

import { describeError } from "../api/errors.js";

import type { ReactNode } from "react";

/**
 * The row a page's or a panel's action buttons sit in.
 *
 * A header's actions are almost always `btn-sm`, which is 32px tall - fine beside
 * a mouse pointer, under the 44px a thumb needs. Sized here through a descendant
 * selector rather than at each call site, for the same reason the shell sizes its
 * drawer entries that way: the buttons are a caller's children, and a rule per
 * page is a rule somebody forgets.
 */
const ACTION_ROW =
  "flex max-sm:w-full flex-wrap gap-2 max-sm:[&_.btn]:min-h-11 max-sm:[&_.btn]:text-base";

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
      <div className="min-w-0">
        <h1 className="text-2xl font-semibold tracking-tight break-words">
          {title}
        </h1>
        {description === undefined ? null : (
          <p className="text-base-content/70 mt-1 max-w-2xl text-sm max-sm:text-base break-words">
            {description}
          </p>
        )}
      </div>
      {actions === undefined ? null : (
        <div className={ACTION_ROW}>{actions}</div>
      )}
    </header>
  );
}

interface PanelProps {
  /** Anchor target, for a link that scrolls to this panel. */
  readonly id?: string;
  readonly title?: string;
  readonly description?: ReactNode;
  readonly actions?: ReactNode;
  readonly children: ReactNode;
}

/** A titled card. The console's only container. */
export function Panel({
  id,
  title,
  description,
  actions,
  children,
}: Readonly<PanelProps>) {
  return (
    <section
      id={id}
      className="card bg-base-100 border-base-300 mb-6 border shadow-sm"
    >
      {/* Every button a panel contains is sized here rather than at its call
          site. daisyUI's `btn-sm` is 32px and 12px, and `btn-xs` is 24px and
          11px - both under the 44px a thumb needs and the 16px the floor asks
          for - and the console has more than a dozen of them scattered through
          panel bodies, so a rule per button is a rule somebody forgets. */}
      <div className="card-body max-sm:p-4 max-sm:[--card-fs:1rem] gap-4 max-sm:[&_.btn]:min-h-11 max-sm:[&_.btn]:text-base">
        {title === undefined && actions === undefined ? null : (
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              {title === undefined ? null : (
                <h2 className="card-title text-base break-words">{title}</h2>
              )}
              {description === undefined ? null : (
                <p className="text-base-content/70 text-sm max-sm:text-base break-words">
                  {description}
                </p>
              )}
            </div>
            {actions === undefined ? null : (
              <div className={ACTION_ROW}>{actions}</div>
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
    <div className="border-base-300 rounded-box border border-dashed px-6 py-10 text-center max-sm:px-4 max-sm:py-8">
      <div className="text-base-content/40 mb-3 flex justify-center">
        <InboxIcon size={24} />
      </div>
      <p className="font-medium">{title}</p>
      <p className="text-base-content/70 mx-auto mt-2 max-w-md text-sm max-sm:text-base">
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
    <div role="alert" className="alert alert-error max-sm:text-base">
      <XCircleIcon className="shrink-0" />
      <div className="min-w-0 break-words">
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
    <div role="status" className="alert alert-info max-sm:text-base">
      <InfoIcon className="shrink-0" />
      <div className="min-w-0 break-words">{children}</div>
    </div>
  );
}

/**
 * What a "check this remote thing" button says before it has anything to show.
 *
 * Two console pages ask Signet to reach out to somebody else's server and report
 * back - the upstream identity provider's discovery document, and a trust anchor's
 * published keys - and the three answers that are not the answer are identical for
 * both: the request itself failed, nobody has pressed the button yet, or the far
 * end replied with a problem. Only the success has anything page-specific in it,
 * so only the success is the caller's to render.
 *
 * The caller narrows its own result before passing children, because a component
 * boundary loses the narrowing: `children` is built by the caller and shown here
 * only when there is something to show.
 *
 * `result` is the check's outcome, or undefined before it has run; `error` is why
 * the request itself failed, if it did; `children` is what a success looks like.
 */
export function CheckOutcome({
  result,
  error,
  children,
}: Readonly<{
  readonly result:
    | { readonly ok: true }
    | {
        readonly ok: false;
        readonly problem: string;
        readonly description: string;
      }
    | undefined;
  readonly error: unknown;
  readonly children: ReactNode;
}>) {
  if (error !== null && error !== undefined) {
    return <ErrorAlert message={describeError(error)} />;
  }
  if (result === undefined) {
    return null;
  }
  if (!result.ok) {
    return <ErrorAlert message={`${result.problem}: ${result.description}`} />;
  }
  return <>{children}</>;
}

/** The placeholder shown while a query is in flight. */
export function Loading({ label }: Readonly<{ readonly label?: string }>) {
  return (
    <div className="flex items-center gap-3 py-8" role="status">
      <span className="loading loading-spinner loading-md" />
      <span className="text-base-content/70 text-sm max-sm:text-base">
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
      <dd className="min-w-0 text-sm break-words sm:col-span-2">{children}</dd>
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
 *
 * The button is icon-only, and reports its own success: the copy icon becomes a
 * green check for a moment, so a press that did something looks different from a
 * press that did not.
 */
export function CopyableValue({
  value,
  label,
}: Readonly<{ readonly value: string; readonly label?: string }>) {
  const [copied, setCopied] = useState(false);

  return (
    <div className="flex items-center gap-2">
      <code className="bg-base-200 rounded-field min-w-0 flex-1 overflow-x-auto px-2 py-1 font-mono text-xs">
        {value}
      </code>
      <button
        type="button"
        className="btn btn-ghost btn-xs max-sm:min-h-11 max-sm:min-w-11"
        aria-label={label === undefined ? "Copy" : `Copy ${label}`}
        onClick={() => {
          void navigator.clipboard.writeText(value);
          setCopied(true);
          setTimeout(() => {
            setCopied(false);
          }, 2000);
        }}
      >
        {copied ? <CheckIcon className="text-success" /> : <CopyIcon />}
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
    <div
      className="alert alert-warning items-start max-sm:text-base"
      role="status"
    >
      <AlertIcon className="shrink-0" />
      <div className="min-w-0 flex-1">
        <p className="font-medium">{title}</p>
        <p className="mt-1 mb-2 text-sm max-sm:text-base">
          Copy it now. It is stored only as a hash, so this is the one time it
          can be read - a lost credential is rotated, not recovered.
        </p>
        <CopyableValue value={value} label={title} />
      </div>
    </div>
  );
}
