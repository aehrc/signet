/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  endpointAccessBody,
  endpointAccessFormValues,
  endpointAccessRows,
  endUserCreateBody,
  endUserFormValues,
  endUserPatch,
  mergeCandidateLists,
} from "./endUserEdit.js";

import type { EndUserCreateForm } from "./endUserEdit.js";
import type { EndpointAccessView, EndUserView } from "../api/types.js";

/** A user as the API returns them, with the fields a case cares about overridden. */
function userView(overrides: Partial<EndUserView> = {}): EndUserView {
  return {
    id: "user-1",
    username: "johngrimes",
    displayName: "John Grimes",
    email: null,
    emailVerified: false,
    roles: ["clinician"],
    attributes: {},
    isPersona: false,
    hasPassword: true,
    disabledAt: null,
    createdAt: "2026-08-03T14:02:11.000Z",
    endpoints: [],
    ...overrides,
  };
}

/** One endpoint's access, with the fields a case cares about overridden. */
function accessView(
  overrides: Partial<EndpointAccessView> = {},
): EndpointAccessView {
  return {
    slug: "ward",
    name: "Ward",
    kind: "smart",
    authMode: "local",
    fhirUser: "Practitioner/clin-001",
    defaultContext: null,
    grantedAt: "2026-08-04T09:00:00.000Z",
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
    // One role per line, which is what the parser round-trips exactly.
    expect(values.roles).toBe("clinician\nresearcher");
  });

  it("renders an email address and whether it is verified", () => {
    const values = endUserFormValues(
      userView({ email: "jo@example.org", emailVerified: true }),
    );

    expect(values.email).toBe("jo@example.org");
    expect(values.emailVerified).toBe(true);
  });

  it("renders an absent email address as an empty field", () => {
    expect(endUserFormValues(userView({ email: null })).email).toBe("");
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

  it("sends a new email address, trimmed", () => {
    const current = userView();
    const patch = endUserPatch(
      { ...endUserFormValues(current), email: "  jo@example.org " },
      current,
    );

    expect(patch).toEqual({ email: "jo@example.org" });
  });

  it("clears an email address with null rather than an empty string", () => {
    // The schema validates an email's shape, so "" would be refused rather than
    // read as "remove it".
    const current = userView({ email: "jo@example.org" });
    const patch = endUserPatch(
      { ...endUserFormValues(current), email: "" },
      current,
    );

    expect(patch).toEqual({ email: null });
  });

  it("sends the verified flag only when it changed", () => {
    const current = userView({ email: "jo@example.org" });
    expect(
      endUserPatch(
        { ...endUserFormValues(current), emailVerified: true },
        current,
      ),
    ).toEqual({ emailVerified: true });
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

  it("can never carry the per-endpoint fields", () => {
    // fhirUser and the default context live on the account's access to one
    // endpoint now, so the account's patch cannot name them.
    const current = userView({ endpoints: [accessView()] });
    const patch = endUserPatch(
      { ...endUserFormValues(current), displayName: "Renamed" },
      current,
    );

    expect(patch).not.toHaveProperty("fhirUserReference");
    expect(patch).not.toHaveProperty("defaultContext");
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

describe("endUserCreateBody", () => {
  /** A filled-in create form, with the fields a case cares about overridden. */
  function createForm(
    overrides: Partial<EndUserCreateForm> = {},
  ): EndUserCreateForm {
    return {
      username: "jo",
      displayName: "Jo Bloggs",
      password: "correct horse",
      isPersona: false,
      invite: false,
      email: "",
      emailVerified: false,
      roles: "",
      ...overrides,
    };
  }

  it("sends a local account's password, and nothing left blank", () => {
    expect(endUserCreateBody(createForm())).toEqual({
      username: "jo",
      displayName: "Jo Bloggs",
      isPersona: false,
      password: "correct horse",
    });
  });

  it("sends no password for a persona", () => {
    expect(
      endUserCreateBody(createForm({ isPersona: true })),
    ).not.toHaveProperty("password");
  });

  it("sends no password for an account invited to choose its own", () => {
    expect(endUserCreateBody(createForm({ invite: true }))).not.toHaveProperty(
      "password",
    );
  });

  it("sends the email and its verified flag, trimmed", () => {
    // The account belongs to the tenant, so its email is not tied to a kind of
    // endpoint: it is released wherever the email scope is granted.
    expect(
      endUserCreateBody(
        createForm({ email: " jo@example.org ", emailVerified: true }),
      ),
    ).toMatchObject({ email: "jo@example.org", emailVerified: true });
  });

  it("leaves a blank email out", () => {
    const body = endUserCreateBody(createForm({ emailVerified: true }));
    expect(body).not.toHaveProperty("email");
    expect(body).not.toHaveProperty("emailVerified");
  });

  it("parses roles one per line", () => {
    expect(
      endUserCreateBody(createForm({ roles: "clinician\n\n nurse " })),
    ).toMatchObject({ roles: ["clinician", "nurse"] });
  });

  it("never sends the per-endpoint fields", () => {
    // They are set on the account's access to an endpoint, after it is created.
    const body = endUserCreateBody(createForm({ isPersona: true }));
    expect(body).not.toHaveProperty("fhirUserReference");
    expect(body).not.toHaveProperty("defaultContext");
  });
});

describe("endpointAccessFormValues", () => {
  it("renders the fhirUser reference and the context fields", () => {
    const values = endpointAccessFormValues(
      accessView({
        defaultContext: {
          patient: "pat-1",
          encounter: "enc-2",
          intent: "reconcile",
        },
      }),
    );

    expect(values).toEqual({
      fhirUser: "Practitioner/clin-001",
      defaultPatient: "pat-1",
      defaultEncounter: "enc-2",
      intent: "reconcile",
    });
  });

  it("renders absent values as empty fields", () => {
    // Not the string "null", which is what a naive `String(value)` would show.
    expect(endpointAccessFormValues(accessView({ fhirUser: null }))).toEqual({
      fhirUser: "",
      defaultPatient: "",
      defaultEncounter: "",
      intent: "",
    });
  });
});

describe("endpointAccessBody", () => {
  it("is empty when nothing was edited", () => {
    const current = accessView({ defaultContext: { patient: "pat-1" } });
    expect(
      endpointAccessBody(endpointAccessFormValues(current), current, true),
    ).toEqual({});
  });

  it("sends a changed fhirUser reference, trimmed", () => {
    const current = accessView();
    expect(
      endpointAccessBody(
        { ...endpointAccessFormValues(current), fhirUser: " Patient/p-3 " },
        current,
        false,
      ),
    ).toEqual({ fhirUserReference: "Patient/p-3" });
  });

  it("clears a fhirUser reference with null rather than an empty string", () => {
    // The API reads null as "clear this" and refuses an empty string.
    const current = accessView();
    expect(
      endpointAccessBody(
        { ...endpointAccessFormValues(current), fhirUser: "  " },
        current,
        false,
      ),
    ).toEqual({ fhirUserReference: null });
  });

  it("leaves an unchanged blank fhirUser reference out", () => {
    const current = accessView({ fhirUser: null });
    expect(
      endpointAccessBody(endpointAccessFormValues(current), current, false),
    ).toEqual({});
  });

  it("sends a persona's default context of only the fields filled in", () => {
    const current = accessView();
    expect(
      endpointAccessBody(
        {
          ...endpointAccessFormValues(current),
          defaultPatient: " pat-1 ",
          intent: "reconcile",
        },
        current,
        true,
      ),
    ).toEqual({ defaultContext: { patient: "pat-1", intent: "reconcile" } });
  });

  it("clears a persona's emptied default context with null", () => {
    // An empty object would store a context whose mere presence is a signal.
    const current = accessView({ defaultContext: { patient: "pat-1" } });
    expect(
      endpointAccessBody(
        { ...endpointAccessFormValues(current), defaultPatient: "" },
        current,
        true,
      ),
    ).toEqual({ defaultContext: null });
  });

  it("leaves an unchanged default context out", () => {
    const current = accessView({
      defaultContext: { patient: "pat-1", intent: "reconcile" },
    });
    expect(
      endpointAccessBody(endpointAccessFormValues(current), current, true),
    ).toEqual({});
  });

  it("never sends a default context for a local account", () => {
    // Only a persona is seeded with a launch context; a local account's comes
    // from the launch.
    const current = accessView();
    expect(
      endpointAccessBody(
        { ...endpointAccessFormValues(current), defaultPatient: "pat-1" },
        current,
        false,
      ),
    ).toEqual({});
  });

  it("sends nothing at all for an OAuth endpoint", () => {
    // The server refuses both fields there, so whatever the form holds is dropped.
    const current = accessView({ kind: "oauth", fhirUser: null });
    expect(
      endpointAccessBody(
        {
          fhirUser: "Practitioner/1",
          defaultPatient: "pat-1",
          defaultEncounter: "",
          intent: "",
        },
        current,
        true,
      ),
    ).toEqual({});
  });
});

describe("endpointAccessRows", () => {
  const endpoints = [
    { slug: "ward", name: "Ward", kind: "smart", authMode: "local" },
    { slug: "notes", name: "Notes", kind: "oauth", authMode: "oidc" },
  ] as const;

  it("gives every endpoint of the tenant a row, in the tenant's order", () => {
    const rows = endpointAccessRows(endpoints, [accessView()]);
    expect(rows.map((row) => row.endpoint.slug)).toEqual(["ward", "notes"]);
  });

  it("pairs each endpoint with the user's access to it, or none", () => {
    const access = accessView();
    const rows = endpointAccessRows(endpoints, [access]);
    expect(rows[0]?.access).toBe(access);
    expect(rows[1]?.access).toBeUndefined();
  });

  it("ignores access to an endpoint the list does not hold", () => {
    // Deny by default: a row is offered only for an endpoint the tenant lists.
    const rows = endpointAccessRows(endpoints, [accessView({ slug: "gone" })]);
    expect(rows.every((row) => row.access === undefined)).toBe(true);
  });
});
