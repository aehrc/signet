/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  endUserFormValues,
  endUserPatch,
  mergeCandidateLists,
} from "./endUserEdit.js";

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

describe("mergeCandidateLists", () => {
  it("replaces the two keys it owns", () => {
    expect(
      mergeCandidateLists({ patients: ["old"] }, ["p1", "p2"], ["e1"]),
    ).toEqual({ patients: ["p1", "p2"], encounters: ["e1"] });
  });

  it("removes an emptied key rather than storing an empty list", () => {
    // A stored `patients: []` and a missing `patients` mean the same thing to the
    // picker, and the smaller record is the one worth keeping.
    expect(
      mergeCandidateLists({ patients: ["p1"], encounters: ["e1"] }, [], []),
    ).toEqual({});
  });

  it("copies every other key through untouched", () => {
    // FR-004: the PATCH replaces the whole attributes record, so a key this form
    // knows nothing about survives only if the form carries it back.
    const merged = mergeCandidateLists(
      { team: "renal", cohort: { id: 7 }, patients: ["p1"] },
      ["p2"],
      [],
    );

    expect(merged).toEqual({
      team: "renal",
      cohort: { id: 7 },
      patients: ["p2"],
    });
  });

  it("does not mutate the record it was given", () => {
    const existing = { patients: ["p1"] };
    mergeCandidateLists(existing, ["p2"], []);
    expect(existing).toEqual({ patients: ["p1"] });
  });
});

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

  it("spreads the default context across its three fields", () => {
    const values = endUserFormValues(
      userView({
        defaultContext: {
          patient: "pat-1",
          encounter: "enc-2",
          intent: "reconcile",
        },
      }),
    );

    expect(values.defaultPatient).toBe("pat-1");
    expect(values.defaultEncounter).toBe("enc-2");
    expect(values.intent).toBe("reconcile");
  });

  it("renders an absent default context as three empty fields", () => {
    const values = endUserFormValues(userView({ defaultContext: null }));

    expect(values.defaultPatient).toBe("");
    expect(values.defaultEncounter).toBe("");
    expect(values.intent).toBe("");
  });

  it("renders the candidate lists one entry per line", () => {
    const values = endUserFormValues(
      userView({
        attributes: { patients: ["p1", "p2"], encounters: ["e1"] },
      }),
    );

    expect(values.patients).toBe("p1\np2");
    expect(values.encounters).toBe("e1");
  });

  it("ignores an attributes value that is not a list of strings", () => {
    // The record is opaque to the rest of the console, so nothing guarantees the
    // shape. A field showing "[object Object]" would be worse than an empty one.
    const values = endUserFormValues(
      userView({ attributes: { patients: "pat-1", encounters: [1, "e1"] } }),
    );

    expect(values.patients).toBe("");
    expect(values.encounters).toBe("e1");
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

  it("clears an emptied default context with null", () => {
    // FR-003: an empty object would store a context whose mere presence is a
    // signal, so clearing has to be explicit.
    const current = userView({ defaultContext: { patient: "pat-1" } });
    const patch = endUserPatch(
      { ...endUserFormValues(current), defaultPatient: "  " },
      current,
    );

    expect(patch).toEqual({ defaultContext: null });
  });

  it("sends a default context of only the fields that were filled in", () => {
    const current = userView();
    const patch = endUserPatch(
      {
        ...endUserFormValues(current),
        defaultPatient: " pat-1 ",
        intent: "reconcile",
      },
      current,
    );

    expect(patch).toEqual({
      defaultContext: { patient: "pat-1", intent: "reconcile" },
    });
  });

  it("leaves an unchanged default context out of the patch", () => {
    const current = userView({
      defaultContext: { patient: "pat-1", intent: "reconcile" },
    });
    expect(endUserPatch(endUserFormValues(current), current)).toEqual({});
  });

  it("leaves an absent default context out of the patch when still blank", () => {
    // The distinction that matters: nothing changed, so no `defaultContext: null`
    // may be sent - that would be a write where the operator made no edit.
    const current = userView({ defaultContext: null });
    expect(endUserPatch(endUserFormValues(current), current)).toEqual({});
  });

  it("sends the whole merged attributes record when a list changes", () => {
    const current = userView({
      attributes: { team: "renal", patients: ["p1"] },
    });
    const patch = endUserPatch(
      { ...endUserFormValues(current), patients: "p2" },
      current,
    );

    expect(patch).toEqual({ attributes: { team: "renal", patients: ["p2"] } });
  });

  it("removes an emptied list from the attributes it sends", () => {
    const current = userView({ attributes: { patients: ["p1"] } });
    const patch = endUserPatch(
      { ...endUserFormValues(current), patients: "" },
      current,
    );

    expect(patch).toEqual({ attributes: {} });
  });

  it("leaves unchanged attributes out of the patch", () => {
    const current = userView({
      attributes: { team: "renal", patients: ["p1"], encounters: ["e1"] },
    });
    expect(endUserPatch(endUserFormValues(current), current)).toEqual({});
  });

  it("changes only the list that was edited", () => {
    const current = userView({
      attributes: { patients: ["p1"], encounters: ["e1"] },
    });
    const patch = endUserPatch(
      { ...endUserFormValues(current), encounters: "e1\ne2" },
      current,
    );

    expect(patch).toEqual({
      attributes: { patients: ["p1"], encounters: ["e1", "e2"] },
    });
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
