/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Wording for management page entries.
 *
 * A standing grant and token-only access are different facts, and the sentence under
 * each app says which one the person is looking at. Kept as a plain function so the
 * page stays a thin wrapper and the wording is testable without a browser.
 *
 * Author: John Grimes
 */

import { formatInstant } from "../formatting/values.js";

/** The facts the description is built from. */
export interface DescribableEntry {
  /** Whether a stored consent backs this entry, making it a standing grant. */
  readonly standing: boolean;
  readonly active: boolean;
  readonly grantedAt: string;
  readonly revokedAt: string | null;
}

/**
 * The one-line description under an app's name on the management page.
 *
 * @param entry - The entry's lifecycle facts.
 * @returns A sentence fragment: when the grant was allowed or withdrawn, that it
 *   expired, or - for access backed only by tokens - since when the app has had it.
 */
export function describeEntry(entry: DescribableEntry): string {
  if (!entry.standing) {
    return `Has access since ${formatInstant(entry.grantedAt)}`;
  }
  if (entry.active) {
    return `Allowed on ${formatInstant(entry.grantedAt)}`;
  }
  // An expired grant was never withdrawn, and "withdrawn on never" is nonsense.
  return entry.revokedAt === null
    ? "Expired"
    : `Withdrawn on ${formatInstant(entry.revokedAt)}`;
}
