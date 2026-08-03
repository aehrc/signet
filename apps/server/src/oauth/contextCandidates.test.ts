import { describe, expect, it } from "vitest";

import {
  contextCandidates,
  isSelectableContextValue,
  soleCandidate,
} from "./contextCandidates.js";

import type { CandidateSource } from "./contextCandidates.js";

const empty: CandidateSource = {
  fhirUserReference: null,
  defaultContext: null,
  attributes: {},
};

describe("contextCandidates", () => {
  it("offers the user's own record when they are a patient", () => {
    expect(
      contextCandidates(
        { ...empty, fhirUserReference: "Patient/pat-1" },
        "patient",
      ),
    ).toEqual(["pat-1"]);
  });

  it("does not offer a practitioner as a patient", () => {
    expect(
      contextCandidates(
        { ...empty, fhirUserReference: "Practitioner/prac-1" },
        "patient",
      ),
    ).toEqual([]);
  });

  it("offers a persona's default context", () => {
    expect(
      contextCandidates(
        { ...empty, defaultContext: { patient: "pat-2", encounter: "enc-2" } },
        "patient",
      ),
    ).toEqual(["pat-2"]);
    expect(
      contextCandidates(
        { ...empty, defaultContext: { patient: "pat-2", encounter: "enc-2" } },
        "encounter",
      ),
    ).toEqual(["enc-2"]);
  });

  it("offers the configured attribute list", () => {
    expect(
      contextCandidates(
        { ...empty, attributes: { patients: ["pat-3", "Patient/pat-4"] } },
        "patient",
      ),
    ).toEqual(["pat-3", "pat-4"]);
    expect(
      contextCandidates(
        { ...empty, attributes: { encounters: ["enc-3"] } },
        "encounter",
      ),
    ).toEqual(["enc-3"]);
  });

  it("puts the user's own record first, then the default, then the list", () => {
    expect(
      contextCandidates(
        {
          fhirUserReference: "Patient/self",
          defaultContext: { patient: "default" },
          attributes: { patients: ["listed"] },
        },
        "patient",
      ),
    ).toEqual(["self", "default", "listed"]);
  });

  it("deduplicates, however each entry was written", () => {
    expect(
      contextCandidates(
        {
          fhirUserReference: "Patient/pat-1",
          defaultContext: { patient: "pat-1" },
          attributes: { patients: ["Patient/pat-1", "pat-1"] },
        },
        "patient",
      ),
    ).toEqual(["pat-1"]);
  });

  it("drops identifiers that are not valid FHIR ids", () => {
    expect(
      contextCandidates(
        { ...empty, attributes: { patients: ["ok", "not ok", "a/b", ""] } },
        "patient",
      ),
    ).toEqual(["ok"]);
  });

  it("ignores an attributes entry that is not a list of strings", () => {
    expect(
      contextCandidates(
        { ...empty, attributes: { patients: "pat-1" } },
        "patient",
      ),
    ).toEqual([]);
    expect(
      contextCandidates(
        { ...empty, attributes: { patients: [1, 2, "pat-1"] } },
        "patient",
      ),
    ).toEqual(["pat-1"]);
  });
});

describe("soleCandidate", () => {
  it("resolves a single candidate without asking", () => {
    expect(soleCandidate(["only"])).toBe("only");
  });

  it("asks when there is a choice, or nothing to choose", () => {
    expect(soleCandidate(["a", "b"])).toBeUndefined();
    expect(soleCandidate([])).toBeUndefined();
  });
});

describe("isSelectableContextValue", () => {
  it("permits a listed candidate", () => {
    expect(isSelectableContextValue(["pat-1"], "pat-1", false)).toBe(true);
  });

  it("refuses an unlisted value on a production endpoint", () => {
    expect(isSelectableContextValue(["pat-1"], "pat-9", false)).toBe(false);
    expect(isSelectableContextValue([], "pat-9", false)).toBe(false);
  });

  it("permits an unlisted but well-formed value on a non-production endpoint", () => {
    expect(isSelectableContextValue([], "pat-9", true)).toBe(true);
  });

  it("refuses a malformed value even on a non-production endpoint", () => {
    expect(isSelectableContextValue([], "not an id", true)).toBe(false);
    expect(isSelectableContextValue([], "", true)).toBe(false);
  });
});
