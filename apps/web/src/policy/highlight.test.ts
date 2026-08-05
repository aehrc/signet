/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { lineForPath, tokenise } from "./highlight.js";

/** The concatenated token text, which must always equal the input. */
function rendered(text: string): string {
  return tokenise(text)
    .map((token) => token.text)
    .join("");
}

describe("tokenise", () => {
  it("loses nothing", () => {
    // The highlighted output is rendered behind the textarea and has to line up
    // character for character, so this is the property that matters most.
    for (const text of [
      '{"a": 1}',
      '{\n  "a": [1, 2, 3],\n  "b": true\n}',
      "not json at all",
      '{"unterminated": "abc',
      "",
    ]) {
      expect(rendered(text)).toBe(text);
    }
  });

  it("distinguishes a key from a string value", () => {
    const tokens = tokenise('{"match": "patient/*.rs"}');
    expect(tokens.find((token) => token.text === '"match"')?.kind).toBe("key");
    expect(tokens.find((token) => token.text === '"patient/*.rs"')?.kind).toBe(
      "string",
    );
  });

  it("marks a template value, because that is what a policy is made of", () => {
    const tokens = tokenise('{"fhirUser": "{{ user.fhirUser }}"}');
    expect(tokens.find((token) => token.text.includes("{{"))?.kind).toBe(
      "template",
    );
  });

  it("colours numbers and keywords", () => {
    const tokens = tokenise('{"ttl": 300, "enabled": false, "note": null}');
    expect(tokens.find((token) => token.text === "300")?.kind).toBe("number");
    expect(tokens.find((token) => token.text === "false")?.kind).toBe(
      "keyword",
    );
    expect(tokens.find((token) => token.text === "null")?.kind).toBe("keyword");
  });

  it("does not mistake a hyphen inside a string for a number", () => {
    const tokens = tokenise('{"id": "grant-read"}');
    expect(tokens.some((token) => token.kind === "number")).toBe(false);
  });

  it("keeps an escaped quote inside its string", () => {
    const text = String.raw`{"a": "say \"hello\""}`;
    expect(rendered(text)).toBe(text);
    const strings = tokenise(text).filter((token) => token.kind === "string");
    expect(strings).toHaveLength(1);
  });

  it("survives a value that is still being typed", () => {
    expect(rendered('{"a": ')).toBe('{"a": ');
  });
});

describe("lineForPath", () => {
  const text = [
    "{",
    '  "version": 1,',
    '  "scopeGrants": [',
    "    {",
    '      "match": "patient/*.rs",',
    '      "allow": true',
    "    }",
    "  ],",
    '  "defaults": {',
    '    "accessTokenTtl": 300',
    "  }",
    "}",
  ].join("\n");

  it("finds a top-level key", () => {
    expect(lineForPath(text, "defaults")).toBe(9);
  });

  it("finds a nested key", () => {
    expect(lineForPath(text, "defaults.accessTokenTtl")).toBe(10);
  });

  it("skips array indices, which have no key of their own", () => {
    expect(lineForPath(text, "scopeGrants.0.match")).toBe(5);
  });

  it("has no line for the document as a whole", () => {
    expect(lineForPath(text, "")).toBeUndefined();
  });

  it("gives up rather than guessing when the key is absent", () => {
    expect(lineForPath(text, "notAKey")).toBeUndefined();
  });
});
