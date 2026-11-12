/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { smartOnlySettingsEnabled } from "./endpointKind.js";

describe("smartOnlySettingsEnabled", () => {
  it("accepts settings that turn nothing SMART-only on", () => {
    expect(
      smartOnlySettingsEnabled({
        supportsEhrLaunch: false,
        supportsV2Scopes: undefined,
        userAccessBrandBundle: null,
      }),
    ).toEqual([]);
  });

  it("names every SMART-only flag set to true", () => {
    expect(
      smartOnlySettingsEnabled({
        supportsStandaloneLaunch: true,
        supportsPatientScopes: true,
        supportsUserScopes: false,
      }),
    ).toEqual(["supportsStandaloneLaunch", "supportsPatientScopes"]);
  });

  it("names a user-access brand that is set", () => {
    expect(
      smartOnlySettingsEnabled({
        userAccessBrandIdentifier: "acme",
      }),
    ).toEqual(["userAccessBrandIdentifier"]);
  });
});
