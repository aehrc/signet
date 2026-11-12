/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * What the end-user pages are told about a tenant's branding.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { isCurrentLogoVersion, tenantBranding } from "./view.js";

const TENANT = { slug: "acme", name: "Acme Health" };
const LIGHT_AT = new Date("2026-03-01T00:00:00.000Z");
const DARK_AT = new Date("2026-03-02T00:00:00.000Z");

describe("tenantBranding", () => {
  it("is null for a tenant with no logo, which keeps the Signet wordmark", () => {
    expect(tenantBranding(TENANT, [])).toBeNull();
  });

  it("names the tenant and versions the logo's URL by when it was stored", () => {
    expect(
      tenantBranding(TENANT, [{ variant: "light", updatedAt: LIGHT_AT }]),
    ).toEqual({
      name: "Acme Health",
      logoUrl: `/t/acme/logo/light?v=${String(LIGHT_AT.getTime())}`,
      darkLogoUrl: null,
    });
  });

  it("offers the dark variant beside the logo", () => {
    expect(
      tenantBranding(TENANT, [
        { variant: "light", updatedAt: LIGHT_AT },
        { variant: "dark", updatedAt: DARK_AT },
      ])?.darkLogoUrl,
    ).toBe(`/t/acme/logo/dark?v=${String(DARK_AT.getTime())}`);
  });

  it("ignores a dark variant with no logo beside it", () => {
    // Only reachable through a race between storing the variant and removing the
    // logo, and a variant of nothing must not brand the pages on its own.
    expect(
      tenantBranding(TENANT, [{ variant: "dark", updatedAt: DARK_AT }]),
    ).toBeNull();
  });

  it("escapes a slug that is not URL-safe", () => {
    expect(
      tenantBranding({ slug: "a b", name: "Spaced" }, [
        { variant: "light", updatedAt: LIGHT_AT },
      ])?.logoUrl,
    ).toStartWith("/t/a%20b/logo/light?v=");
  });
});

describe("isCurrentLogoVersion", () => {
  it("accepts the version the branding view hands out", () => {
    expect(isCurrentLogoVersion(String(LIGHT_AT.getTime()), LIGHT_AT)).toBe(
      true,
    );
  });

  it("refuses an older version, and an absent one", () => {
    expect(isCurrentLogoVersion("1", LIGHT_AT)).toBe(false);
    expect(isCurrentLogoVersion(undefined, LIGHT_AT)).toBe(false);
  });
});
