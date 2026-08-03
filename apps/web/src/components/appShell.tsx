import type { ReactNode } from "react";

interface AppShellProps {
  /** Shown in the navbar beside the Signet mark. */
  readonly title: string;
  /** Navigation entries rendered in the sidebar. */
  readonly navigation?: ReactNode;
  readonly children: ReactNode;
}

/**
 * The frame shared by the console, the end-user auth pages and the developer
 * portal, so all three surfaces stay visually identical.
 *
 * Every colour comes from a daisyUI semantic token rather than a literal
 * palette value, which is what lets the whole product re-theme from one word in
 * `styles.css`.
 */
export function AppShell({
  title,
  navigation,
  children,
}: Readonly<AppShellProps>) {
  return (
    <div className="drawer lg:drawer-open">
      <input id="signet-drawer" type="checkbox" className="drawer-toggle" />

      <div className="drawer-content flex flex-col">
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
