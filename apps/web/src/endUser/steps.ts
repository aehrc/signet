/**
 * Which page a step belongs on.
 *
 * The server decides what the user must do next and answers every request with that
 * step; the browser's job is to be on the matching page. Those are two different things
 * and this is the mapping between them - the same one the server uses when it redirects
 * from `/authorize`, restated here because the pages navigate between themselves without
 * going back through it.
 *
 * Pure and tested. Getting it wrong does not fail loudly: the page simply stays where it
 * is, showing a form for a step that has already been completed.
 *
 * Author: John Grimes
 */

import type { InteractionStep } from "./api.js";

/** The path segment each step is rendered at, under the endpoint's issuer. */
const STEP_PAGES: Readonly<Record<string, string>> = {
  login: "/login",
  "select-context": "/picker",
  consent: "/consent",
};

/**
 * The page a step is rendered at, or undefined when it is not rendered at all.
 *
 * `complete` and `denied` have no page: both carry a redirect to the app, and the
 * browser leaves rather than rendering anything.
 *
 * @param step - The step the interaction API reported.
 */
export function pageForStep(step: InteractionStep): string | undefined {
  return STEP_PAGES[step];
}

/**
 * Where to send the browser next, or undefined to stay put.
 *
 * Returns a path with the session identifier attached, so a navigation between steps
 * keeps the flow addressable - a reload of the picker must land on the picker.
 *
 * @param currentPath - The path being rendered now.
 * @param step - The step the interaction API reported.
 * @param sessionId - The authorization session's identifier.
 */
export function nextStepPath(
  currentPath: string,
  step: InteractionStep,
  sessionId: string,
): string | undefined {
  const page = pageForStep(step);
  if (page === undefined) {
    return undefined;
  }
  // The issuer prefix is whatever precedes the page segment in the current path, which
  // keeps this free of any assumption about how the endpoint is addressed.
  const base = currentPath.replace(/\/(?:login|picker|consent)\/?$/, "");
  const target = `${base}${page}`;
  if (currentPath.replace(/\/$/, "") === target) {
    return undefined;
  }
  return `${target}?session=${encodeURIComponent(sessionId)}`;
}
