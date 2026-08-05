/**
 * Turning a user into a form, and a form into a patch.
 *
 * The page that uses this is a thin composition; everything here is where the
 * decisions actually are, so this is where they can be tested without a browser.
 *
 * Two of those decisions are worth stating. The API's PATCH writes only the fields a
 * request names, so a save sends the changed ones and nothing else - a form that sent
 * everything would overwrite what another operator changed while this page was open.
 * And a blank is not the same as an absence: a cleared `fhirUser` field means "remove
 * the reference", which the API takes as an explicit `null`, while a field nobody
 * touched must not appear in the body at all.
 *
 * Author: John Grimes
 */

import { changedFields, formatList, parseList } from "./lists.js";

import type { EndUserView } from "../api/types.js";

/** The flat, all-text shape the user edit form holds. */
export interface EndUserFormValues {
  readonly displayName: string;
  readonly fhirUser: string;
  /** Roles, one per line. */
  readonly roles: string;
}

/**
 * Reads a user's current values into the form.
 *
 * @param user - The user as the API returns them.
 * @returns The values the form renders when nothing has been edited.
 */
export function endUserFormValues(user: EndUserView): EndUserFormValues {
  return {
    displayName: user.displayName,
    fhirUser: user.fhirUser ?? "",
    roles: formatList(user.roles),
  };
}

/**
 * Builds the PATCH body for a set of edits.
 *
 * Carries only what differs from what was loaded, so a save with no changes produces
 * an empty object and sends nothing. The username is absent by construction: the form
 * has no field for it, and the API would refuse one anyway.
 *
 * @param edited - The form's current values.
 * @param current - The user as loaded.
 * @returns The patch, which may be empty.
 * @example
 * endUserPatch({ ...values, fhirUser: "" }, user); // { fhirUserReference: null }
 */
export function endUserPatch(
  edited: EndUserFormValues,
  current: EndUserView,
): Record<string, unknown> {
  const fhirUser = edited.fhirUser.trim();

  return changedFields<Record<string, unknown>>(
    {
      displayName: edited.displayName,
      // Null rather than "": the API reads the first as "clear this" and refuses
      // the second, which is not a distinction the operator should have to make.
      fhirUserReference: fhirUser.length === 0 ? null : fhirUser,
      roles: parseList(edited.roles),
    },
    {
      displayName: current.displayName,
      fhirUserReference: current.fhirUser,
      roles: [...current.roles],
    },
  );
}
