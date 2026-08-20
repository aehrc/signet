/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * How a lifecycle status reads.
 *
 * Kept apart from the components so that a status word is coloured the same way
 * wherever it appears: "suspended" must not be a warning on the client list and grey
 * on the client's own page. Clients, endpoints, keys and registration requests share
 * the vocabulary, so they share this.
 *
 * Author: John Grimes
 */

/** How a status reads: neutral, good, warning or bad. */
export type BadgeTone = "neutral" | "success" | "warning" | "error" | "info";

/**
 * The tone for a status value from the API.
 *
 * An unrecognised value is neutral rather than an error: during a rolling upgrade the
 * server may name a state this bundle has never heard of, and colouring it red would
 * invent a problem.
 *
 * @param status - A status value from the API.
 */
export function toneForStatus(status: string): BadgeTone {
  switch (status) {
    case "active":
    case "approved": {
      return "success";
    }
    case "next":
    case "pending": {
      return "info";
    }
    case "suspended":
    case "disabled": {
      return "warning";
    }
    case "rejected": {
      return "error";
    }
    default: {
      return "neutral";
    }
  }
}
