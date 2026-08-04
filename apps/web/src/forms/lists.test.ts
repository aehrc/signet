/**
 * Author: John Grimes
 */

import { describe, expect, it } from "vitest";

import {
  changedFields,
  formatList,
  formatScopeList,
  parseList,
  parsePositiveInteger,
  parseScopeList,
} from "./lists.js";

describe("parseList", () => {
  it("splits on newlines", () => {
    expect(parseList("a\nb")).toEqual(["a", "b"]);
  });

  it("splits on commas too", () => {
    // A list pasted out of a configuration file arrives either way.
    expect(parseList("a, b")).toEqual(["a", "b"]);
  });

  it("drops blank lines and trims", () => {
    expect(parseList(" a \n\n  \n b \n")).toEqual(["a", "b"]);
  });

  it("returns an empty list for empty text", () => {
    expect(parseList("")).toEqual([]);
    expect(parseList("   \n ")).toEqual([]);
  });
});

describe("formatList", () => {
  it("round-trips through parseList", () => {
    const values = ["https://a.test/cb", "https://b.test/cb"];
    expect(parseList(formatList(values))).toEqual(values);
  });

  it("treats an absent list as empty", () => {
    expect(formatList(undefined)).toBe("");
  });
});

describe("parseScopeList", () => {
  it("splits on whitespace", () => {
    expect(parseScopeList("openid fhirUser")).toEqual(["openid", "fhirUser"]);
  });

  it("does not split inside a scope's search parameters", () => {
    // `patient/Observation.rs?category=a,b` is one scope. Splitting on commas
    // would silently turn it into two, neither of them valid.
    expect(
      parseScopeList("patient/Observation.rs?category=a,b openid"),
    ).toEqual(["patient/Observation.rs?category=a,b", "openid"]);
  });

  it("accepts one per line", () => {
    expect(parseScopeList("openid\npatient/*.rs")).toEqual([
      "openid",
      "patient/*.rs",
    ]);
  });

  it("round-trips", () => {
    const scopes = ["openid", "patient/*.rs"];
    expect(parseScopeList(formatScopeList(scopes))).toEqual(scopes);
  });
});

describe("parsePositiveInteger", () => {
  it("reads a number", () => {
    expect(parsePositiveInteger("300")).toBe(300);
  });

  it("refuses anything that is not a positive integer", () => {
    expect(parsePositiveInteger("")).toBeUndefined();
    expect(parsePositiveInteger("abc")).toBeUndefined();
    expect(parsePositiveInteger("-5")).toBeUndefined();
    expect(parsePositiveInteger("1.5")).toBeUndefined();
    expect(parsePositiveInteger("0")).toBeUndefined();
  });

  it("tolerates surrounding whitespace", () => {
    expect(parsePositiveInteger("  60 ")).toBe(60);
  });
});

describe("changedFields", () => {
  it("keeps only what differs", () => {
    expect(
      changedFields(
        { name: "new", description: "same" },
        {
          name: "old",
          description: "same",
        },
      ),
    ).toEqual({ name: "new" });
  });

  it("compares arrays by contents", () => {
    expect(changedFields({ uris: ["a", "b"] }, { uris: ["a", "b"] })).toEqual(
      {},
    );
    expect(changedFields({ uris: ["b", "a"] }, { uris: ["a", "b"] })).toEqual({
      uris: ["b", "a"],
    });
  });

  it("treats a length change as a change", () => {
    expect(changedFields({ uris: ["a"] }, { uris: ["a", "b"] })).toEqual({
      uris: ["a"],
    });
  });

  it("distinguishes clearing a field from leaving it alone", () => {
    // The API writes only the fields a request names, so an explicit null must
    // survive as a change while an unchanged undefined must not appear at all.
    expect(
      changedFields<{ note: string | null }>(
        { note: null },
        { note: "something" },
      ),
    ).toEqual({ note: null });
    expect(changedFields({ note: undefined }, { note: undefined })).toEqual({});
  });

  it("includes a field the original did not have", () => {
    expect(changedFields({ name: "a" }, {})).toEqual({ name: "a" });
  });
});
