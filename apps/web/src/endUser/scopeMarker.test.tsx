/**
 * The scope list marker, asserted from server-rendered markup.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

import { ScopeMarker } from "./scopeMarker.js";

describe("ScopeMarker", () => {
  it("marks a write scope with a warning-toned alert octicon", () => {
    const markup = renderToStaticMarkup(<ScopeMarker writes />);
    expect(markup).toContain("octicon-alert");
    expect(markup).toContain("text-warning");
  });

  it("marks a read scope with a muted dot octicon", () => {
    const markup = renderToStaticMarkup(<ScopeMarker writes={false} />);
    expect(markup).toContain("octicon-dot-fill");
    expect(markup).not.toContain("octicon-alert");
  });

  it("hides itself from assistive technology", () => {
    // The marker decorates the scope description; the words carry the meaning.
    const markup = renderToStaticMarkup(<ScopeMarker writes />);
    expect(markup).toContain('aria-hidden="true"');
  });

  it("passes a class through to the wrapper", () => {
    const markup = renderToStaticMarkup(
      <ScopeMarker writes className="mr-2" />,
    );
    expect(markup).toContain("mr-2");
  });
});
