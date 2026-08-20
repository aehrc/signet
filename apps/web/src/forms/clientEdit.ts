/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Turning a client into a form, and a form into a patch.
 *
 * The page that uses this is a thin composition; the decisions are here, so this is
 * where they can be tested without a browser.
 *
 * The one that matters most: a save with nothing changed must produce an empty patch,
 * and the page must be able to see that before the operator presses anything. The
 * admin API accepts an empty PATCH body and records a `client.updated` audit event
 * naming no fields - a write to an append-only trail describing an edit that never
 * happened.
 *
 * Author: John Grimes
 */

import {
  changedFields,
  formatList,
  formatScopeList,
  parseList,
  parseScopeList,
} from "./lists.js";

import type { ClientView } from "../api/types.js";

/** The flat, all-text shape the client edit form holds. */
export interface ClientFormValues {
  readonly name: string;
  readonly status: string;
  /** Redirect URIs, one per line. */
  readonly redirectUris: string;
  /** Allowed scopes, one per line. */
  readonly allowedScopes: string;
}

/**
 * Reads a client's current values into the form.
 *
 * @param client - The client as the API returns it.
 * @returns The values the form renders when nothing has been edited.
 * @example
 * clientFormValues(client).redirectUris; // "https://app.example.com/cb"
 */
export function clientFormValues(client: ClientView): ClientFormValues {
  return {
    name: client.name,
    status: client.status,
    redirectUris: formatList(client.redirectUris),
    allowedScopes: formatScopeList(client.allowedScopes),
  };
}

/**
 * Builds the PATCH body for a set of edits.
 *
 * Carries only what differs from what was loaded, so a save with no changes produces
 * an empty object and the page sends nothing. Sending every field on every save would
 * also overwrite a value another operator changed while this page was open.
 *
 * @param edited - The form's current values.
 * @param current - The client as loaded.
 * @returns The patch, which may be empty.
 * @example
 * clientPatch({ ...values, status: "suspended" }, client); // { status: "suspended" }
 */
export function clientPatch(
  edited: ClientFormValues,
  current: ClientView,
): Record<string, unknown> {
  return changedFields<Record<string, unknown>>(
    {
      name: edited.name,
      status: edited.status,
      redirectUris: parseList(edited.redirectUris),
      allowedScopes: parseScopeList(edited.allowedScopes),
    },
    {
      name: current.name,
      status: current.status,
      redirectUris: [...current.redirectUris],
      allowedScopes: [...current.allowedScopes],
    },
  );
}
