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

  it("keeps its own width when the description beside it wraps", () => {
    // In a flex row a 12px icon is the item a browser will shrink first, and a
    // squashed marker is the difference between a read and a write going
    // unnoticed on a narrow screen.
    expect(renderToStaticMarkup(<ScopeMarker writes />)).toContain("shrink-0");
  });

  it("lays the wrapper out inline-flex so the icon cannot break the line", () => {
    // Tailwind's preflight sets `display: block` on svg, so a marker in a
    // non-flex list item would otherwise push the description onto its own line.
    const markup = renderToStaticMarkup(<ScopeMarker writes={false} />);
    expect(markup).toContain("inline-flex");
  });
});
