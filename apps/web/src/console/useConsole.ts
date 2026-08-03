/**
 * Reading what the layouts established.
 *
 * Two hooks, both thin wrappers over the router's outlet context. They exist so a
 * page says `useConsoleContext()` rather than repeating a generic parameter that, if
 * mistyped, would silently widen to the wrong shape.
 *
 * Both throw when used outside their layout. That is a programming error rather than
 * a runtime condition — a page can only be reached through its layout — and throwing
 * gives the mistake a name instead of an `undefined` several lines later.
 */

import { useOutletContext } from "react-router";

import type { ConsoleContext } from "./consoleLayout.js";
import type { EndpointContext } from "./endpointLayout.js";

/** The signed-in session, the tenant in the URL, and the role held in it. */
export function useConsoleContext(): ConsoleContext {
  const context = useOutletContext<ConsoleContext | undefined>();
  if (context === undefined) {
    throw new Error("useConsoleContext used outside the console layout");
  }
  return context;
}

/** The above, plus the endpoint in the URL and its configuration. */
export function useEndpointContext(): EndpointContext {
  const context = useOutletContext<EndpointContext | undefined>();
  if (context === undefined) {
    throw new Error("useEndpointContext used outside the endpoint layout");
  }
  return context;
}

/**
 * Whether a role is at least the one required.
 *
 * The same total order the server enforces, restated here for one purpose: hiding a
 * control the caller may not use. It is not a security check — the API refuses
 * regardless — but showing a viewer a "Delete" button that always fails is a worse
 * interface than not showing it.
 *
 * @param held - The role the caller holds in this tenant.
 * @param required - The minimum the action needs.
 */
export function roleAllows(held: string, required: string): boolean {
  const rank: Readonly<Record<string, number>> = {
    viewer: 0,
    developer: 1,
    admin: 2,
    owner: 3,
  };
  return (rank[held] ?? -1) >= (rank[required] ?? Number.POSITIVE_INFINITY);
}
