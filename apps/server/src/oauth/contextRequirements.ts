/**
 * Which launch context an authorization needs before it can be granted.
 *
 * Read from the requested scopes, and read in two places: once at `/authorize`,
 * to refuse a request for context the endpoint does not offer, and again on each
 * step of the interaction, to decide whether the user still has a patient to pick.
 * The two must agree, so the rule lives here rather than in either of them.
 *
 * A patient is needed for `launch/patient` and also for any `patient/` resource
 * scope. The second is the one that is easy to miss: an app asking for
 * `patient/Observation.rs` without `launch/patient` has still asked for a token
 * whose meaning depends on which patient is in context, and the SMART baseline
 * policy's `requireContext: [patient]` will deny it outright if none is resolved.
 * Treating that as "no context needed" would produce an authorization that
 * completes and then grants nothing.
 *
 * Author: John Grimes
 */

import type { LaunchContext, Scope } from "@signet/core";

/** The launch context keys an authorization must resolve. */
export interface ContextRequirements {
  readonly patient: boolean;
  readonly encounter: boolean;
}

/**
 * Derives the context requirements from a set of requested scopes.
 *
 * @param scopes - The requested scopes, parsed and normalised to v2.
 */
export function contextRequirements(
  scopes: readonly Scope[],
): ContextRequirements {
  return {
    patient: scopes.some(
      (scope) =>
        (scope.kind === "launch" && scope.resource === "patient") ||
        (scope.kind === "resource" && scope.context === "patient"),
    ),
    encounter: scopes.some(
      (scope) => scope.kind === "launch" && scope.resource === "encounter",
    ),
  };
}

/**
 * Whether a resolved context satisfies the requirements.
 *
 * An empty string does not satisfy a requirement. The distinction matters because
 * a picker that submits a blank field would otherwise appear to have chosen
 * something, and the token would carry `patient: ""`.
 */
export function requirementsSatisfied(
  requirements: ContextRequirements,
  resolved: LaunchContext | null,
): boolean {
  if (requirements.patient && (resolved?.patient ?? "").length === 0) {
    return false;
  }
  return !(requirements.encounter && (resolved?.encounter ?? "").length === 0);
}
