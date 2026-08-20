/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

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

  it("reads its trigger at 16px below sm", () => {
    // `btn-sm` is 12px, and the trigger carries the signed-in identity - the
    // one thing in the navbar somebody reads rather than presses.
    expect(markup).toContain("max-w-48 max-sm:min-h-11 max-sm:text-base");
  });

  it("reads the bare sign-out button at 16px below sm", () => {
    // The shape a personal access token gets: no menu, one button.
    const bare = renderToStaticMarkup(
      <AccountMenu
        label="ci-token"
        signingOut={false}
        onSignOut={() => undefined}
      />,
    );
    expect(bare).toContain(
      "btn btn-ghost btn-sm max-sm:min-h-11 max-sm:text-base",
    );
  });
});
