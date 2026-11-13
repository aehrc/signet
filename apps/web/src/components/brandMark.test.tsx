/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The mark at the top of every page: a tenant's logo, or the Signet wordmark.
 *
 * Asserted from server-rendered markup. Which of the two images a browser actually
 * picks in a dark colour scheme is the browser's business, and is checked by eye;
 * what is asserted here is that it is offered the choice.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

import { CentredShell } from "./appShell.js";
import { BrandingContext } from "./brandingContext.js";
import { BrandMark } from "./brandMark.js";

import type { TenantBranding } from "@signet/core";

const BRANDING: TenantBranding = {
  name: "Acme Health",
  logoUrl: "/t/acme/logo/light?v=1",
  darkLogoUrl: null,
};

/** Renders the mark under a given branding. */
function render(branding: TenantBranding | null | undefined): string {
  return renderToStaticMarkup(
    <BrandingContext value={branding}>
      <BrandMark />
    </BrandingContext>,
  );
}

describe("BrandMark", () => {
  it("shows the Signet wordmark when nothing provides a branding", () => {
    const markup = renderToStaticMarkup(<BrandMark />);
    expect(markup).toContain("Signet");
    expect(markup).not.toContain("<img");
  });

  it("shows the Signet wordmark for a tenant with no logo", () => {
    expect(render(null)).toContain("Signet");
  });

  it("shows the tenant's logo in place of the wordmark, named by the tenant", () => {
    const markup = render(BRANDING);
    expect(markup).toContain('src="/t/acme/logo/light?v=1"');
    expect(markup).toContain('alt="Acme Health"');
    expect(markup).not.toContain("Signet");
  });

  it("offers the dark variant to a dark colour scheme only", () => {
    const markup = render({
      ...BRANDING,
      darkLogoUrl: "/t/acme/logo/dark?v=2",
    });
    expect(markup).toContain('srcSet="/t/acme/logo/dark?v=2"');
    expect(markup).toContain('media="(prefers-color-scheme: dark)"');
  });

  it("offers no alternative when there is no dark variant", () => {
    expect(render(BRANDING)).not.toContain("<source");
  });

  it("shows neither while the branding is still loading", () => {
    // Showing the wordmark and then swapping in a logo would flash Signet's name on
    // a page that is about to carry somebody else's.
    const markup = render(undefined);
    expect(markup).not.toContain("Signet");
    expect(markup).not.toContain("<img");
  });
});

describe("CentredShell", () => {
  it("carries the tenant's logo when a branding is provided", () => {
    const markup = renderToStaticMarkup(
      <BrandingContext value={BRANDING}>
        <CentredShell title="Sign in">
          <p>form</p>
        </CentredShell>
      </BrandingContext>,
    );
    expect(markup).toContain('alt="Acme Health"');
    expect(markup).not.toContain(">Signet<");
  });
});
