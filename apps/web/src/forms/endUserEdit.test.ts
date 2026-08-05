/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { endUserFormValues, endUserPatch } from "./endUserEdit.js";

import type { EndUserView } from "../api/types.js";

/** A user as the API returns them, with the fields a case cares about overridden. */
function userView(overrides: Partial<EndUserView> = {}): EndUserView {
  return {
    id: "user-1",
    username: "johngrimes",
    displayName: "John Grimes",
    fhirUser: "Practitioner/clin-001",
    roles: ["clinician"],
    attributes: {},
    defaultContext: null,
    isPersona: false,
    hasPassword: true,
    disabledAt: null,
    createdAt: "2026-08-03T14:02:11.000Z",
    ...overrides,
  };
}

describe("endUserFormValues", () => {
  it("renders the profile fields as the form holds them", () => {
    const values = endUserFormValues(
      userView({ roles: ["clinician", "researcher"] }),
    );

    expect(values.displayName).toBe("John Grimes");
    expect(values.fhirUser).toBe("Practitioner/clin-001");
    // One role per line, which is what the parser round-trips exactly.
    expect(values.roles).toBe("clinician\nresearcher");
  });

  it("renders an absent fhirUser reference as an empty field", () => {
    // Not the string "null", which is what a naive `String(value)` would show.
    expect(endUserFormValues(userView({ fhirUser: null })).fhirUser).toBe("");
  });
});

describe("endUserPatch", () => {
  it("is empty when nothing was edited", () => {
    // FR-009: a save with no changes sends nothing at all.
    const current = userView();
    expect(endUserPatch(endUserFormValues(current), current)).toEqual({});
  });

  it("carries only the field that changed", () => {
    const current = userView();
    const patch = endUserPatch(
      { ...endUserFormValues(current), displayName: "John A Grimes" },
      current,
    );

    expect(patch).toEqual({ displayName: "John A Grimes" });
  });

  it("clears a fhirUser reference with null rather than an empty string", () => {
    // The API distinguishes the two: null clears the column, "" fails validation.
    const current = userView();
    const patch = endUserPatch(
      { ...endUserFormValues(current), fhirUser: "   " },
      current,
    );

    expect(patch).toEqual({ fhirUserReference: null });
  });

  it("trims a fhirUser reference before sending it", () => {
    const current = userView();
    const patch = endUserPatch(
      { ...endUserFormValues(current), fhirUser: "  Patient/pat-3  " },
      current,
    );

    expect(patch).toEqual({ fhirUserReference: "Patient/pat-3" });
  });

  it("leaves an unchanged blank fhirUser reference out of the patch", () => {
    const current = userView({ fhirUser: null });
    expect(endUserPatch(endUserFormValues(current), current)).toEqual({});
  });

  it("parses roles one per line", () => {
    const current = userView({ roles: [] });
    const patch = endUserPatch(
      { ...endUserFormValues(current), roles: " clinician \n\n researcher \n" },
      current,
    );

    expect(patch).toEqual({ roles: ["clinician", "researcher"] });
  });

  it("treats a reordered role list as a change", () => {
    // Order is what the operator typed, and the API stores the array as given.
    const current = userView({ roles: ["a", "b"] });
    const patch = endUserPatch(
      { ...endUserFormValues(current), roles: "b\na" },
      current,
    );

    expect(patch).toEqual({ roles: ["b", "a"] });
  });

  it("can never carry a username", () => {
    // FR-008: the username is not editable anywhere in the console, and the form
    // has no field for it - this asserts the patch cannot grow one by accident.
    const current = userView();
    const patch = endUserPatch(
      { ...endUserFormValues(current), displayName: "Renamed" },
      current,
    );

    expect(Object.keys(patch)).not.toContain("username");
  });
});
