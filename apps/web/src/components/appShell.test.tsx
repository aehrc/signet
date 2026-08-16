/**
 * The shell's icons, asserted from server-rendered markup.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

import { AppShell } from "./appShell.js";

describe("AppShell", () => {
  const markup = renderToStaticMarkup(
    <AppShell title="Demo">
      <p>content</p>
    </AppShell>,
  );

  it("draws the drawer toggle with the three-bars octicon", () => {
    expect(markup).toContain("octicon-three-bars");
  });

  it("keeps the toggle's accessible name", () => {
    expect(markup).toContain('aria-label="Open navigation"');
  });
});
