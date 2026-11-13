/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { linkifyText } from "./linkify.js";

describe("linkifyText", () => {
  it("returns nothing for an empty string", () => {
    expect(linkifyText("")).toEqual([]);
  });

  it("leaves text with no address in it as one text segment", () => {
    expect(linkifyText("Ask your administrator for an account.")).toEqual([
      { kind: "text", text: "Ask your administrator for an account." },
    ]);
  });

  it("links an email address to mailto, leaving the sentence around it", () => {
    // The full stop after the address ends the sentence; it is not part of the domain.
    expect(
      linkifyText("Contact us at pathling@csiro.au if you want an account."),
    ).toEqual([
      { kind: "text", text: "Contact us at " },
      {
        kind: "link",
        text: "pathling@csiro.au",
        href: "mailto:pathling@csiro.au",
      },
      { kind: "text", text: " if you want an account." },
    ]);
  });

  it("links an http or https URL to itself, query string included", () => {
    expect(
      linkifyText("See https://example.org/accounts?type=new and http://a.b/c"),
    ).toEqual([
      { kind: "text", text: "See " },
      {
        kind: "link",
        text: "https://example.org/accounts?type=new",
        href: "https://example.org/accounts?type=new",
      },
      { kind: "text", text: " and " },
      { kind: "link", text: "http://a.b/c", href: "http://a.b/c" },
    ]);
  });

  it("leaves trailing punctuation outside a URL", () => {
    // A URL at the end of a sentence or inside parentheses would otherwise carry
    // the full stop or the closing bracket into its href and 404.
    expect(linkifyText("Apply (https://example.org/apply).")).toEqual([
      { kind: "text", text: "Apply (" },
      {
        kind: "link",
        text: "https://example.org/apply",
        href: "https://example.org/apply",
      },
      { kind: "text", text: ")." },
    ]);
  });

  it("does not link a scheme other than http and https", () => {
    // The message is operator text, but the link it becomes is clicked by end users,
    // so a script-executing scheme must stay inert text.
    expect(linkifyText("javascript:alert(1) or ftp://example.org/x")).toEqual([
      { kind: "text", text: "javascript:alert(1) or ftp://example.org/x" },
    ]);
  });

  it("treats a URL carrying credentials as one URL, not as an email address", () => {
    expect(linkifyText("https://user@example.org/path")).toEqual([
      {
        kind: "link",
        text: "https://user@example.org/path",
        href: "https://user@example.org/path",
      },
    ]);
  });

  it("keeps line breaks in the text segments", () => {
    // Rendering preserves them; this function must not swallow them.
    expect(linkifyText("Line one.\nEmail a@b.org\nLine three.")).toEqual([
      { kind: "text", text: "Line one.\nEmail " },
      { kind: "link", text: "a@b.org", href: "mailto:a@b.org" },
      { kind: "text", text: "\nLine three." },
    ]);
  });
});
