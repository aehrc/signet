/**
 * The shell's icons and its mobile sizing, asserted from server-rendered markup.
 *
 * The sizing assertions are about classes rather than about measured pixels,
 * because static markup has no layout: what a unit test can hold is that the
 * shell asks for a 44px target and 16px text below `sm`. That the browser then
 * gives it is measured by `e2e/tests/responsive.spec.ts` at a real viewport.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

import { AppShell, CentredShell } from "./appShell.js";

/**
 * The markup with its attribute escaping undone.
 *
 * Tailwind's arbitrary variants contain `&`, which React escapes inside an
 * attribute value, so the class as written in the source is not the string that
 * appears in the output.
 *
 * @param markup - Server-rendered markup.
 * @returns The same markup with `&amp;` read back as `&`.
 */
function unescaped(markup: string): string {
  return markup.replaceAll("&amp;", "&");
}

describe("AppShell", () => {
  const markup = renderToStaticMarkup(
    <AppShell
      title="Demo"
      navigation={
        <li>
          <a href="/console">Endpoints</a>
        </li>
      }
    >
      <p>content</p>
    </AppShell>,
  );

  it("draws the drawer toggle with the three-bars octicon", () => {
    expect(markup).toContain("octicon-three-bars");
  });

  it("keeps the toggle's accessible name", () => {
    expect(markup).toContain('aria-label="Open navigation"');
  });

  it("gives the drawer toggle a 44px touch target below sm", () => {
    // daisyUI's square button is 40px, which is under the touch minimum. The
    // bump is responsive so desktop density is left alone.
    expect(markup).toContain("max-sm:min-h-11");
    expect(markup).toContain("max-sm:min-w-11");
  });

  it("gives every drawer navigation entry a 44px touch target below sm", () => {
    // The entries are a caller's children, so the shell can only size them
    // through a descendant selector on the menu it puts them in.
    expect(unescaped(markup)).toContain("max-sm:[&_a]:min-h-11");
  });

  it("reads navigation entries at 16px below sm", () => {
    // daisyUI's menu is 14px, which mobile browsers treat as small text.
    expect(unescaped(markup)).toContain("max-sm:[&_a]:text-base");
  });

  it("clips a long title rather than letting it widen the navbar", () => {
    // A tenant name is whatever its owner typed, and one long word with no
    // break opportunity in it would otherwise push the navbar - and with it the
    // page - wider than the viewport. The full name is still on the tenant
    // switcher beside it.
    expect(markup).toContain("min-w-0 flex-1 truncate px-2");
  });

  it("keeps the content column from being widened by what is inside it", () => {
    // `drawer-content` is a grid item, and a grid item's automatic minimum size
    // is its content's - so one over-wide child stretches the column, which is
    // the page scrolling sideways one level up.
    expect(markup).toContain("drawer-content flex min-h-screen min-w-0");
  });

  it("narrows the main area's padding below sm", () => {
    // 24px of padding either side of a 360px viewport is 13% of the width.
    expect(markup).toContain("flex-1 p-4 sm:p-6");
  });
});

describe("CentredShell", () => {
  const markup = renderToStaticMarkup(
    <CentredShell
      title="Sign in"
      subtitle="To continue"
      footer={<a href="/apps">Register an app</a>}
    >
      <p>content</p>
    </CentredShell>,
  );

  it("narrows the page padding below sm so the card fits 360px", () => {
    expect(markup).toContain("justify-center p-4 sm:p-6");
  });

  it("narrows the card's own padding below sm", () => {
    expect(markup).toContain("card-body max-sm:p-4");
  });

  it("restores 16px as the body size inside the card below sm", () => {
    // The same daisyUI card default the console's panels carry: `--card-fs` is
    // 0.875rem, so a consent screen's own text renders at 14px unless the
    // property is put back.
    expect(markup).toContain("max-sm:[--card-fs:1rem]");
  });

  it("reads its subtitle at 16px below sm", () => {
    // The sentence saying what is being asked of the reader, on the surfaces
    // where mobile is the normal case rather than the exception.
    expect(markup).toContain("mt-1 text-sm max-sm:text-base");
  });

  it("reads its footer at 16px below sm", () => {
    expect(markup).toContain("text-center text-sm max-sm:text-base");
  });

  it("reads the card's buttons at 16px below sm", () => {
    // "Allow", "Deny", "Sign in": the three most consequential presses in the
    // product, all of them daisyUI's 14px default.
    expect(unescaped(markup)).toContain("max-sm:[&_.btn]:text-base");
  });
});
