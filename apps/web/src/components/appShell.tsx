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
 * the moments where there is exactly one thing to do — signing in, choosing a
 * tenant, consenting. Giving those a sidebar would offer navigation that either does
 * not work yet or is not the point.
 */

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
  return (
    <div className="drawer lg:drawer-open">
      <input id="signet-drawer" type="checkbox" className="drawer-toggle" />

      <div className="drawer-content flex min-h-screen flex-col">
        <header className="navbar bg-base-100 border-base-300 border-b">
          <div className="flex-none lg:hidden">
            <label
              htmlFor="signet-drawer"
              className="btn btn-square btn-ghost"
              aria-label="Open navigation"
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                className="h-5 w-5"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                aria-hidden="true"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  d="M4 6h16M4 12h16M4 18h16"
                />
              </svg>
            </label>
          </div>
          <div className="flex-1 px-2">
            <span className="text-lg font-semibold tracking-tight">
              {title}
            </span>
          </div>
          {navbarEnd === undefined ? null : (
            <div className="flex-none gap-2 px-2">{navbarEnd}</div>
          )}
        </header>

        <main className="bg-base-200 flex-1 p-6">{children}</main>
      </div>

      <div className="drawer-side">
        <label
          htmlFor="signet-drawer"
          aria-label="Close navigation"
          className="drawer-overlay"
        />
        <nav className="bg-base-100 border-base-300 min-h-full w-64 border-r p-4">
          <div className="px-2 pb-4 text-xl font-bold">Signet</div>
          <ul className="menu w-full">{navigation}</ul>
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
    <div className="bg-base-200 flex min-h-screen items-center justify-center p-6">
      <div className="w-full max-w-md">
        <div className="mb-6 text-center">
          <p className="text-xl font-bold">Signet</p>
        </div>
        <div className="card bg-base-100 border-base-300 border shadow-sm">
          <div className="card-body gap-4">
            <div>
              <h1 className="card-title text-lg">{title}</h1>
              {subtitle === undefined ? null : (
                <p className="text-base-content/70 mt-1 text-sm">{subtitle}</p>
              )}
            </div>
            {children}
          </div>
        </div>
        {footer === undefined ? null : (
          <div className="text-base-content/70 mt-4 text-center text-sm">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}
