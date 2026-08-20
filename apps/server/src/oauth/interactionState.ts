/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The interaction state machine: what the user still has to do.
 *
 * An authorization spans several browser round trips - sign in, pick a patient,
 * consent - and the state that decides which of them is next lives entirely in
 * the `authorization_sessions` row. Nothing is taken from the browser between
 * steps, which is what makes it impossible for a later step to widen an earlier
 * decision: the scopes consented to are the scopes recorded at `/authorize`, not
 * the ones the consent form happened to post back.
 *
 * Deciding the next step is pure, so the whole machine is testable without a
 * database or a browser: given a session's four nullable columns and the
 * endpoint's consent mode, exactly one step is next. The handlers only move the
 * session forward one step at a time and re-derive this after each move, so a user
 * who skips straight to `/consent` gets sent back to sign in.
 *
 * Author: John Grimes
 */

import { requirementsSatisfied } from "./contextRequirements.js";

import type { ContextRequirements } from "./contextRequirements.js";
import type { LaunchContext } from "@signet/core";

/** What the user must do next. */
export type InteractionStep =
  /** Authenticate: password, persona picker or upstream IdP. */
  | "login"
  /** Choose the patient, or the encounter, the session is about. */
  | "select-context"
  /** Approve the scopes the app asked for. */
  | "consent"
  /** Nothing: the authorization can be completed and a code issued. */
  | "complete";

/** How much consent an endpoint asks the end user for. */
export type ConsentMode = "always" | "remember" | "auto";

/** The session state the decision reads. */
export interface InteractionInputs {
  /** Whether an end user has been attached to the session. */
  readonly authenticated: boolean;
  readonly requirements: ContextRequirements;
  readonly resolvedContext: LaunchContext | null;
  /** Whether consent was granted *during this session*. */
  readonly consentGranted: boolean;
  readonly consentMode: ConsentMode;
  /**
   * Whether a stored consent already covers everything this session requests.
   *
   * The caller compares scopes; this module only decides whether that comparison
   * matters, which depends on the endpoint's consent mode.
   */
  readonly hasStoredConsent: boolean;
}

/**
 * Whether the user must be shown a consent screen.
 *
 * `auto` skips it entirely, which is only appropriate for an endpoint whose apps
 * are all first-party - a connectathon sandbox, or a deployment where approval
 * happened out of band at registration time.
 *
 * `remember` skips it when a stored consent covers the request. A stored consent
 * that covers *less* than is being requested does not count, and it is the
 * caller's job to have compared them: the difference is exactly the scope the user
 * has not agreed to.
 */
export function consentRequired(inputs: InteractionInputs): boolean {
  if (inputs.consentGranted) {
    return false;
  }
  switch (inputs.consentMode) {
    case "auto": {
      return false;
    }
    case "remember": {
      return !inputs.hasStoredConsent;
    }
    case "always": {
      return true;
    }
  }
}

/**
 * Decides what the user must do next.
 *
 * The order is not interchangeable. Authentication comes first because both later
 * steps are about a particular user: a patient picker cannot know which patients
 * to offer, and a consent record has nobody to belong to. Context comes before
 * consent because the consent screen has to name the patient being shared -
 * "allow this app to read your records" is not a meaningful question until it is
 * clear whose records.
 *
 * @param inputs - The session's state.
 */
export function decideStep(inputs: InteractionInputs): InteractionStep {
  if (!inputs.authenticated) {
    return "login";
  }
  if (!requirementsSatisfied(inputs.requirements, inputs.resolvedContext)) {
    return "select-context";
  }
  return consentRequired(inputs) ? "consent" : "complete";
}

/** A step the user is sent to a page for. `complete` has no page. */
export type InteractionPageStep = Exclude<InteractionStep, "complete">;

/**
 * Path segment of the end-user page for each step.
 *
 * The names are the ones the plan's URL layout specifies, and they are stable
 * because an end user may bookmark one and a branded deployment may link to it.
 */
const INTERACTION_PATHS: Readonly<Record<InteractionPageStep, string>> = {
  login: "/login",
  "select-context": "/picker",
  consent: "/consent",
};

/**
 * The URL to send the browser to for a step.
 *
 * The session identifier travels in the query string. It is not a bearer
 * credential - it grants nothing on its own, and every handler re-derives the
 * step from the row rather than trusting where the browser came from - so it is
 * safe in a URL the user can see and reload.
 *
 * @param issuer - The endpoint's issuer identifier.
 * @param step - The step to render.
 * @param sessionId - The `authorization_sessions` row identifier.
 */
export function interactionUrl(
  issuer: string,
  step: InteractionPageStep,
  sessionId: string,
): string {
  const url = new URL(`${issuer}${INTERACTION_PATHS[step]}`);
  url.searchParams.set("session", sessionId);
  return url.toString();
}
