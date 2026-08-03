/**
 * The console's URL shapes.
 *
 * Built here rather than interpolated at call sites, for the same reason the API
 * paths are: a link built by hand is a 404 that looks like missing data. Pure and
 * tested.
 *
 * The console mirrors the API's hierarchy — tenant, then endpoint, then resource —
 * because the navigation is that hierarchy and a URL that did not match it would
 * make a bookmark ambiguous about which endpoint it meant.
 */

/** Where the console lives within the application. */
export const CONSOLE_BASE = "/console";

/** The sign-in page. */
export const SIGN_IN_ROUTE = `${CONSOLE_BASE}/sign-in`;

/** Escapes one path segment. */
function segment(value: string): string {
  return encodeURIComponent(value);
}

/** A tenant's endpoint list, and anything else under the tenant. */
export function tenantRoute(tenant: string, suffix = ""): string {
  return `${CONSOLE_BASE}/t/${segment(tenant)}${suffix}`;
}

/** An endpoint, and anything under it. */
export function endpointRoute(
  tenant: string,
  endpoint: string,
  suffix = "",
): string {
  return tenantRoute(tenant, `/e/${segment(endpoint)}${suffix}`);
}

/** One client's detail page. */
export function clientRoute(
  tenant: string,
  endpoint: string,
  clientId: string,
): string {
  return endpointRoute(tenant, endpoint, `/clients/${segment(clientId)}`);
}

/** The tabs an endpoint's pages are reached by, in the order they are shown. */
export const ENDPOINT_TABS: readonly {
  readonly path: string;
  readonly label: string;
}[] = [
  { path: "", label: "Overview" },
  { path: "/clients", label: "Clients" },
  { path: "/policy", label: "Policy" },
  { path: "/users", label: "Users" },
  { path: "/keys", label: "Keys" },
  { path: "/requests", label: "Requests" },
  { path: "/launch", label: "Launch" },
];

/**
 * Which endpoint tab a path is on.
 *
 * Matched by longest suffix rather than by equality, so a client's detail page
 * (`/clients/app-1`) still highlights the Clients tab. Returns the overview tab for
 * the endpoint's own path.
 *
 * @param tenant - The tenant slug.
 * @param endpoint - The endpoint slug.
 * @param path - The current location's pathname.
 */
export function activeEndpointTab(
  tenant: string,
  endpoint: string,
  path: string,
): string {
  const base = endpointRoute(tenant, endpoint);
  if (!path.startsWith(base)) {
    return "";
  }
  const remainder = path.slice(base.length);

  const matches = ENDPOINT_TABS.filter(
    (tab) => tab.path !== "" && remainder.startsWith(tab.path),
  );
  // Longest first, so `/clients` does not win over a hypothetical `/clients-x`.
  const best = matches.toSorted((a, b) => b.path.length - a.path.length)[0];
  return best?.path ?? "";
}
