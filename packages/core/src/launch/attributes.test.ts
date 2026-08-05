/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { attributeStringList } from "./attributes.js";

describe("attributeStringList", () => {
  it("reads the strings under a key", () => {
    expect(attributeStringList({ patients: ["p1", "p2"] }, "patients")).toEqual(
      ["p1", "p2"],
    );
  });

  it("is empty for a key that is not there", () => {
    expect(attributeStringList({}, "patients")).toEqual([]);
  });

  it("is empty for a value that is not an array", () => {
    // An operator writing `patients: "p1"` gets no candidates rather than a picker
    // offering the individual characters of the string.
    expect(attributeStringList({ patients: "p1" }, "patients")).toEqual([]);
  });

  it("drops the elements that are not strings", () => {
    expect(
      attributeStringList(
        { patients: ["p1", 7, null, { id: "p2" }] },
        "patients",
      ),
    ).toEqual(["p1"]);
  });

  it("preserves the stored order", () => {
    // The order is what a picker renders, so it is not incidental.
    expect(attributeStringList({ e: ["b", "a"] }, "e")).toEqual(["b", "a"]);
  });
});
