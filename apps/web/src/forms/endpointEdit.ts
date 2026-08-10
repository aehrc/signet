/**
 * Turning an endpoint into its two forms, and those forms into patches.
 *
 * The page that uses this is a thin composition; the decisions are here, so this is
 * where they can be tested without a browser.
 *
 * The one that matters most: a save with nothing changed must produce an empty patch,
 * and the page must be able to see that before the operator presses anything. The
 * admin API accepts an empty PATCH body and records an `endpoint.updated` audit event
 * naming no fields - a write to an append-only trail describing an edit that never
 * happened.
 *
 * Two others are worth stating.
 *
 * A blank description means "remove it", which the API takes as an explicit `null`,
 * so the form has to make that distinction rather than sending an empty string the
 * schema would store.
 *
 * A lifetime that is not a positive integer is left out of the patch entirely. It
 * cannot be carried as `undefined`: that counts as a change here and then disappears
 * in `JSON.stringify`, so Save would light up and send a body with nothing in it -
 * which is the write this module exists to prevent.
 *
 * The capability flags are top-level keys of the patch rather than a nested record,
 * because that is the shape `endpointPatchSchema` accepts.
 *
 * Author: John Grimes
 */

import { changedFields, parsePositiveInteger } from "./lists.js";

import type { CapabilityFlags, EndpointView } from "../api/types.js";

/** The flat shape the endpoint settings form holds. */
export interface EndpointSettingsFormValues {
  readonly name: string;
  readonly description: string;
  readonly fhirBaseUrl: string;
  /** Seconds, as typed. */
  readonly accessTokenTtl: string;
  /** Seconds, as typed. */
  readonly refreshTokenTtl: string;
  readonly authMode: string;
  readonly consentMode: string;
  readonly isProduction: boolean;
  readonly status: string;
}

/**
 * Reads an endpoint's current values into the settings form.
 *
 * @param endpoint - The endpoint as the API returns it.
 * @returns The values the form renders when nothing has been edited.
 * @example
 * endpointSettingsFormValues(endpoint).accessTokenTtl; // "900"
 */
export function endpointSettingsFormValues(
  endpoint: EndpointView,
): EndpointSettingsFormValues {
  return {
    name: endpoint.name,
    description: endpoint.description ?? "",
    fhirBaseUrl: endpoint.fhirBaseUrl,
    accessTokenTtl: String(endpoint.accessTokenTtl),
    refreshTokenTtl: String(endpoint.refreshTokenTtl),
    authMode: endpoint.authMode,
    consentMode: endpoint.consentMode,
    isProduction: endpoint.isProduction,
    status: endpoint.status,
  };
}

/**
 * Builds the PATCH body for a set of settings edits.
 *
 * Carries only what differs from what was loaded, so a save with no changes produces
 * an empty object and the page sends nothing.
 *
 * @param edited - The form's current values.
 * @param current - The endpoint as loaded.
 * @returns The patch, which may be empty.
 * @example
 * endpointSettingsPatch({ ...values, description: "" }, endpoint);
 * // { description: null }
 */
export function endpointSettingsPatch(
  edited: EndpointSettingsFormValues,
  current: EndpointView,
): Record<string, unknown> {
  const patch = changedFields<Record<string, unknown>>(
    {
      name: edited.name,
      description: edited.description.length === 0 ? null : edited.description,
      fhirBaseUrl: edited.fhirBaseUrl,
      authMode: edited.authMode,
      consentMode: edited.consentMode,
      isProduction: edited.isProduction,
      status: edited.status,
    },
    {
      name: current.name,
      description: current.description,
      fhirBaseUrl: current.fhirBaseUrl,
      authMode: current.authMode,
      consentMode: current.consentMode,
      isProduction: current.isProduction,
      status: current.status,
    },
  );

  const lifetimes: readonly (readonly [string, string, number])[] = [
    ["accessTokenTtl", edited.accessTokenTtl, current.accessTokenTtl],
    ["refreshTokenTtl", edited.refreshTokenTtl, current.refreshTokenTtl],
  ];
  for (const [name, text, loaded] of lifetimes) {
    const value = parsePositiveInteger(text);
    if (value !== undefined && value !== loaded) {
      patch[name] = value;
    }
  }

  return patch;
}

/**
 * Builds the PATCH body for a set of capability toggles.
 *
 * @param flags - The checkboxes as they now stand.
 * @param current - The capabilities as loaded.
 * @returns The patch, which may be empty.
 * @example
 * capabilityPatch({ allowsPublicClients: true }, { allowsPublicClients: false });
 * // { allowsPublicClients: true }
 */
export function capabilityPatch(
  flags: CapabilityFlags,
  current: CapabilityFlags,
): Record<string, boolean> {
  return changedFields<Record<string, boolean>>(flags, current) as Record<
    string,
    boolean
  >;
}
