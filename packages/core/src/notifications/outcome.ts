/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Judging what a round of registration request notifications achieved.
 *
 * Author: John Grimes
 */

/** What became of one round of notifications, as the audit trail records it. */
export type NotificationOutcome =
  | { readonly ok: true; readonly recipients: number }
  | {
      readonly ok: false;
      readonly reason: "no-recipients" | "delivery-failed";
      readonly recipients: number;
      readonly delivered: number;
      readonly errors: readonly string[];
    };

/**
 * Summarises the sends made for one notification.
 *
 * Success means every reviewer was reached. A partial delivery is a failure, so the
 * audit trail shows that somebody was not told, and so is a request with nobody to
 * tell: it would otherwise sit unseen until someone happened to open the console.
 *
 * @param recipients - How many reviewers a message was addressed to.
 * @param failures - An error code for each send that failed.
 * @returns The outcome, with each distinct error code listed once, sorted.
 * @example
 * ```ts
 * summariseNotification(3, ["EENVELOPE"]);
 * // { ok: false, reason: "delivery-failed", recipients: 3, delivered: 2,
 * //   errors: ["EENVELOPE"] }
 * ```
 */
export function summariseNotification(
  recipients: number,
  failures: readonly string[],
): NotificationOutcome {
  if (recipients > 0 && failures.length === 0) {
    return { ok: true, recipients };
  }
  return {
    ok: false,
    reason: recipients === 0 ? "no-recipients" : "delivery-failed",
    recipients,
    delivered: recipients - failures.length,
    errors: [...new Set(failures)].toSorted(),
  };
}
