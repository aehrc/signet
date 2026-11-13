/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The operator's message on the sign-in page, asserted from its server-rendered markup.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

import { LoginMessage } from "./loginMessage.js";

describe("LoginMessage", () => {
  it("renders nothing when the endpoint has no message", () => {
    expect(renderToStaticMarkup(<LoginMessage message={null} />)).toBe("");
  });

  it("links an email address in the message to mailto", () => {
    const markup = renderToStaticMarkup(
      <LoginMessage message="Contact us at pathling@csiro.au if you want an account." />,
    );

    expect(markup).toContain(
      '<a class="link" href="mailto:pathling@csiro.au">pathling@csiro.au</a>',
    );
    expect(markup).toContain("Contact us at ");
    expect(markup).toContain(" if you want an account.");
  });

  it("escapes markup in the message rather than rendering it", () => {
    // The message is shown to every end user of the endpoint, so HTML in it must
    // arrive as text.
    const markup = renderToStaticMarkup(
      <LoginMessage message={'<img src=x onerror="alert(1)">'} />,
    );

    expect(markup).not.toContain("<img");
    expect(markup).toContain("&lt;img");
  });

  it("lets a long address wrap rather than widen the card", () => {
    // A form URL or a long email address is one word with nothing to break at, and
    // `break-words` does not shrink the alert's min-content width, so on a phone
    // the whole sign-in page would scroll sideways.
    const markup = renderToStaticMarkup(
      <LoginMessage message={`https://example.org/${"x".repeat(120)}`} />,
    );

    expect(markup).toContain("wrap-anywhere");
  });

  it("keeps the operator's line breaks", () => {
    const markup = renderToStaticMarkup(
      <LoginMessage message={"Line one.\nLine two."} />,
    );

    expect(markup).toContain("whitespace-pre-line");
    expect(markup).toContain("Line one.\nLine two.");
  });
});
