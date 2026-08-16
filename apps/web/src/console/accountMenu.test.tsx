/**
 * The account menu's icons, asserted from server-rendered markup.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

import { AccountMenu } from "./accountMenu.js";

describe("AccountMenu", () => {
  const markup = renderToStaticMarkup(
    <AccountMenu
      label="alex@example.org"
      signingOut={false}
      onManagePasskeys={() => undefined}
      onSignOut={() => undefined}
    />,
  );

  it("marks the trigger with a chevron octicon rather than a glyph", () => {
    expect(markup).toContain("octicon-chevron-down");
    expect(markup).not.toContain("▾");
  });

  it("marks the passkey item with the passkey octicon", () => {
    expect(markup).toContain("octicon-passkey-fill");
  });

  it("marks the sign-out item with the sign-out octicon", () => {
    expect(markup).toContain("octicon-sign-out");
  });
});
