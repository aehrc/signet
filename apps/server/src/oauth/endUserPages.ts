/**
 * Which paths under an endpoint's issuer are pages rather than API routes.
 *
 * An endpoint's issuer prefix serves both: `{iss}/token` is an API and `{iss}/login` is
 * a page the browser renders. The static-file middleware has to tell them apart, because
 * answering a mistyped API path with the application shell would hand a script a page of
 * HTML and a 200.
 *
 * The set is closed and small, and every name in it is a URL an end user may bookmark or
 * a branded deployment may link to - so it is stated once, here, and read by both the
 * router and the static handler.
 *
 * Author: John Grimes
 */

/** The page names served under an endpoint's issuer. */
export const END_USER_PAGES = [
  /** Sign in, reached from `/authorize`. */
  "login",
  /** Choose the patient or encounter the authorization is about. */
  "picker",
  /** Approve what the app asked for. */
  "consent",
  /** Review and withdraw the access apps hold. SMART's `management_endpoint`. */
  "manage",
  /** The developer portal: ask for a client, and collect it. */
  "apps",
] as const;

/** One of the page names. */
export type EndUserPage = (typeof END_USER_PAGES)[number];

/**
 * Whether a request path is one of the end-user pages.
 *
 * Matches the page path exactly and nothing beneath it: `/manage` is a page, and
 * `/manage/session` is the API the page calls. That distinction is the whole point -
 * without it the shell would be served in place of a 404 for every mistyped route under
 * an issuer.
 *
 * @param path - The request path, as `/t/{tenant}/e/{endpoint}/{page}`.
 */
export function isEndUserPagePath(path: string): boolean {
  const segments = path.split("/").filter((segment) => segment.length > 0);
  if (segments.length !== 5) {
    return false;
  }
  const [t, , e, , page] = segments;
  return (
    t === "t" &&
    e === "e" &&
    page !== undefined &&
    (END_USER_PAGES as readonly string[]).includes(page)
  );
}
