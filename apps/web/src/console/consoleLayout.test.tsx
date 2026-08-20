/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The console frame's own form control, asserted from server-rendered markup.
 *
 * The tenant switcher is the one control in the console that is not built from
 * `components/fields.js`, so it is the one that can miss the mobile sizing those
 * components apply for every other field. It appears only for somebody who
 * belongs to more than one tenant, which the end-to-end stack does not seed, so a
 * markup assertion is what covers it - the browser measurement in
 * `e2e/tests/responsive.spec.ts` never reaches it.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

import { TenantSwitcher } from "./consoleLayout.js";

describe("TenantSwitcher", () => {
  const markup = renderToStaticMarkup(
    <TenantSwitcher
      tenant="demo"
      tenants={[
        { slug: "demo", name: "Demo", role: "admin" },
        { slug: "other", role: "viewer" },
      ]}
    />,
  );

  it("offers a 44px tall target below sm", () => {
    // daisyUI's `select-sm` is 32px, which is the shortest control in the
    // navbar and sits beside the account menu at the edge of the screen.
    expect(markup).toContain("max-sm:min-h-11");
  });

  it("reads at 16px below sm, so opening it does not zoom the page", () => {
    expect(markup).toContain("max-sm:text-base");
  });

  it("selects the tenant the URL names", () => {
    expect(markup).toContain('value="demo"');
  });

  it("falls back to the slug for a tenant with no name", () => {
    expect(markup).toContain(">other</option>");
  });
});
