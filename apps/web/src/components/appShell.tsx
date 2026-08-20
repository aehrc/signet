/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The frame shared by the console, the end-user auth pages and the developer
 * portal, so all three surfaces stay visually identical.
 *
 * Every colour comes from a daisyUI semantic token rather than a literal palette
 * value, which is what lets the whole product re-theme from one word in
 * `styles.css`.
 *
 * Two frames, not one. {@link AppShell} has a navigation drawer and is what an
 * operator works inside; {@link CentredShell} is a single card on an empty page, for
 * the moments where there is exactly one thing to do - signing in, choosing a
 * tenant, consenting. Giving those a sidebar would offer navigation that either does
 * not work yet or is not the point.
 *
 * The `max-sm:` classes are the mobile half of the frame. Below `sm` a control
 * has to be big enough to hit with a thumb (44px) and text has to be big enough
 * that a browser does not zoom to read it (16px); above it, the desktop's denser
 * rendering is what was approved and is left alone. Sizing the drawer's entries
 * through a descendant selector rather than at each call site is deliberate: the
 * entries are a caller's children, and a rule per page is a rule somebody
 * forgets.
 *
 * Author: John Grimes
 */

import { ThreeBarsIcon } from "@primer/octicons-react";
import { useRef } from "react";

import type { ReactNode } from "react";

interface AppShellProps {
  /** Shown in the navbar beside the Signet mark. */
  readonly title: string;
  /** Navigation entries rendered in the sidebar. */
  readonly navigation?: ReactNode;
  /** Rendered at the trailing edge of the navbar: tenant switcher, sign-out. */
  readonly navbarEnd?: ReactNode;
  readonly children: ReactNode;
}

/** The console's frame: a persistent sidebar and a scrolling main area. */
export function AppShell({
  title,
  navigation,
  navbarEnd,
  children,
}: Readonly<AppShellProps>) {
  const toggle = useRef<HTMLInputElement>(null);

  return (
    <div className="drawer lg:drawer-open">
      <input
        ref={toggle}
        id="signet-drawer"
        type="checkbox"
        className="drawer-toggle"
      />

      <div className="drawer-content flex min-h-screen min-w-0 flex-col">
        <header className="navbar bg-base-100 border-base-300 border-b">
          <div className="flex-none lg:hidden">
            <label
              htmlFor="signet-drawer"
              className="btn btn-square btn-ghost max-sm:min-h-11 max-sm:min-w-11"
              aria-label="Open navigation"
            >
              <ThreeBarsIcon />
            </label>
          </div>
          <div className="min-w-0 flex-1 truncate px-2">
            <span className="text-lg font-semibold tracking-tight">
              {title}
            </span>
          </div>
          {navbarEnd === undefined ? null : (
            <div className="flex-none gap-2 px-2">{navbarEnd}</div>
          )}
        </header>

        <main className="bg-base-200 flex-1 p-4 sm:p-6">{children}</main>
      </div>

      <div className="drawer-side">
        <label
          htmlFor="signet-drawer"
          aria-label="Close navigation"
          className="drawer-overlay"
        />
        <nav className="bg-base-100 border-base-300 min-h-full w-64 border-r p-4">
          <div className="px-2 pb-4 text-xl font-bold">Signet</div>
          <ul
            className="menu w-full max-sm:[&_a]:min-h-11 max-sm:[&_a]:text-base"
            // Below `lg` the drawer is an overlay laid over the page it
            // navigates to, and a checkbox does not uncheck itself: without
            // this, choosing an entry leaves the reader on the new page with
            // the drawer still covering it. Caught on the way down to the
            // anchor rather than bound to each entry, because the entries are a
            // caller's children - and the capture phase means the anchor stays
            // the interactive element, so a keyboard activation closes it too.
            // At `lg` the checkbox governs nothing, so this is a no-op there,
            // and it also leaves the toggle unchecked when a narrow window is
            // widened past the breakpoint and then narrowed again.
            onClickCapture={() => {
              if (toggle.current !== null) {
                toggle.current.checked = false;
              }
            }}
          >
            {navigation}
          </ul>
        </nav>
      </div>
    </div>
  );
}

interface CentredShellProps {
  readonly title: string;
  /** One sentence saying where the reader is and what is being asked of them. */
  readonly subtitle?: ReactNode;
  readonly children: ReactNode;
  /** Rendered under the card: links out, or a way to start again. */
  readonly footer?: ReactNode;
}

/** A single card on an empty page, for a surface with one thing to do. */
export function CentredShell({
  title,
  subtitle,
  children,
  footer,
}: Readonly<CentredShellProps>) {
  return (
    <div className="bg-base-200 flex min-h-screen items-center justify-center p-4 sm:p-6">
      <div className="w-full max-w-md">
        <div className="mb-6 text-center">
          <p className="text-xl font-bold">Signet</p>
        </div>
        <div className="card bg-base-100 border-base-300 border shadow-sm">
          <div className="card-body max-sm:p-4 max-sm:[--card-fs:1rem] gap-4 max-sm:[&_.btn]:min-h-11 max-sm:[&_.btn]:text-base">
            <div>
              <h1 className="card-title text-lg">{title}</h1>
              {subtitle === undefined ? null : (
                <p className="text-base-content/70 mt-1 text-sm max-sm:text-base">
                  {subtitle}
                </p>
              )}
            </div>
            {children}
          </div>
        </div>
        {footer === undefined ? null : (
          <div className="text-base-content/70 mt-4 text-center text-sm max-sm:text-base">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}
