/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Which paths under an endpoint's issuer, or under a tenant, are pages rather than API
 * routes.
 *
 * An endpoint's issuer prefix serves both: `{iss}/token` is an API and `{iss}/login` is
 * a page the browser renders. So does a tenant's prefix: `/t/{tenant}/invitation` is a
 * page and `/t/{tenant}/invitation/details` the API it calls. The static-file middleware
 * has to tell them apart, because answering a mistyped API path with the application
 * shell would hand a script a page of HTML and a 200.
 *
 * The sets are closed and small, and every name in them is a URL an end user may
 * bookmark or a branded deployment may link to - so they are stated once, here, and read
 * by the static handler.
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

/** The page names served under a tenant, outside every endpoint. */
export const TENANT_PAGES = [
  /**
   * Choose an account's password, from the link an administrator sent. A tenant page
   * because the account belongs to the tenant, and the password works at every
   * endpoint it has access to.
   */
  "invitation",
] as const;

/**
 * Whether a request path is one of the tenant pages.
 *
 * Matches the page path exactly and nothing beneath it, for the reason
 * {@link isEndUserPagePath} does.
 *
 * @param path - The request path, as `/t/{tenant}/{page}`.
 */
export function isTenantPagePath(path: string): boolean {
  const segments = path.split("/").filter((segment) => segment.length > 0);
  if (segments.length !== 3) {
    return false;
  }
  const [t, , page] = segments;
  return (
    t === "t" &&
    page !== undefined &&
    (TENANT_PAGES as readonly string[]).includes(page)
  );
}
