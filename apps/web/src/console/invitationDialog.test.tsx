/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The invitation dialog's recipient, asserted from server-rendered markup.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

import { InvitationDialog } from "./invitationDialog.js";

/** Renders the dialog for an account with the given recorded address. */
function render(recipient: string | null): string {
  return renderToStaticMarkup(
    <InvitationDialog
      invitation={{
        url: "https://signet.test/t/demo/e/notes/invitation#token",
        createdAt: "2026-11-13T00:00:00.000Z",
        expiresAt: "2026-11-20T00:00:00.000Z",
      }}
      username="nora"
      endpointName="Notes"
      recipient={recipient}
      onClose={() => undefined}
    />,
  );
}

describe("InvitationDialog", () => {
  it("addresses the email to the account's recorded address", () => {
    expect(render("nora@example.org")).toContain("mailto:nora@example.org?");
  });

  it("leaves the recipient blank for an account with no address", () => {
    expect(render(null)).not.toContain("example.org");
  });
});
