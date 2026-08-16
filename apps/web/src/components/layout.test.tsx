/**
 * The layout components' icons, asserted from their server-rendered markup.
 *
 * Rendered with `renderToStaticMarkup` rather than a DOM, because everything under
 * test is presentational: what is asserted is that each component carries the
 * intended octicon (by its `octicon-*` class), that decorative icons are hidden from
 * assistive technology, and that icon-only controls still say what they do in words.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

import {
  CopyableValue,
  EmptyState,
  ErrorAlert,
  InfoAlert,
  ShownOnce,
} from "./layout.js";

describe("EmptyState", () => {
  const markup = renderToStaticMarkup(
    <EmptyState title="No endpoints yet" description="Create one." />,
  );

  it("shows a muted inbox icon above the message", () => {
    expect(markup).toContain("octicon-inbox");
  });

  it("hides the icon from assistive technology", () => {
    // The icon decorates the words beside it; it must not be announced.
    expect(markup).toContain('aria-hidden="true"');
  });
});

describe("ErrorAlert", () => {
  const markup = renderToStaticMarkup(<ErrorAlert message="It broke" />);

  it("carries the error icon", () => {
    expect(markup).toContain("octicon-x-circle");
  });

  it("still carries the message", () => {
    expect(markup).toContain("It broke");
  });
});

describe("InfoAlert", () => {
  it("carries the info icon", () => {
    const markup = renderToStaticMarkup(<InfoAlert>Saved.</InfoAlert>);
    expect(markup).toContain("octicon-info");
  });
});

describe("ShownOnce", () => {
  it("carries the warning icon", () => {
    const markup = renderToStaticMarkup(
      <ShownOnce title="Client secret" value="s3cret" />,
    );
    expect(markup).toContain("octicon-alert");
  });
});

describe("CopyableValue", () => {
  const markup = renderToStaticMarkup(<CopyableValue value="abc" />);

  it("shows a copy icon instead of the word", () => {
    expect(markup).toContain("octicon-copy");
    // Icon-only: the word "Copy" must not appear as button text. It still
    // appears in the accessible name, so assert on the element text only.
    expect(markup).not.toMatch(/>Copy</u);
  });

  it("keeps an accessible name on the icon-only button", () => {
    expect(markup).toContain('aria-label="Copy"');
  });

  it("names the value in the accessible name when labelled", () => {
    const labelled = renderToStaticMarkup(
      <CopyableValue value="abc" label="Issuer" />,
    );
    expect(labelled).toContain('aria-label="Copy Issuer"');
  });
});
