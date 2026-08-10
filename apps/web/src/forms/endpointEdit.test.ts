/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  capabilityPatch,
  endpointSettingsFormValues,
  endpointSettingsPatch,
} from "./endpointEdit.js";

import type { EndpointView } from "../api/types.js";

/** An endpoint as the API returns it, with the fields a case cares about overridden. */
function endpointView(overrides: Partial<EndpointView> = {}): EndpointView {
  return {
    slug: "pathling",
    name: "Pathling",
    description: null,
    fhirBaseUrl: "https://fhir.example.com/fhir",
    issuer: "https://signet.example.com/t/demo/e/pathling",
    smartConfigurationUrl:
      "https://signet.example.com/t/demo/e/pathling/.well-known/smart-configuration",
    status: "active",
    authMode: "local",
    consentMode: "always",
    isProduction: true,
    accessTokenTtl: 900,
    refreshTokenTtl: 86_400,
    scopesSupported: ["patient/*.rs"],
    userAccessBrandBundle: null,
    userAccessBrandIdentifier: null,
    capabilities: { supportsEhrLaunch: true, allowsPublicClients: false },
    createdAt: "2026-08-03T14:02:11.000Z",
    updatedAt: "2026-08-03T14:02:11.000Z",
    ...overrides,
  };
}

describe("endpointSettingsFormValues", () => {
  it("renders the numbers as text and a missing description as blank", () => {
    expect(endpointSettingsFormValues(endpointView())).toEqual({
      name: "Pathling",
      description: "",
      fhirBaseUrl: "https://fhir.example.com/fhir",
      accessTokenTtl: "900",
      refreshTokenTtl: "86400",
      authMode: "local",
      consentMode: "always",
      isProduction: true,
      status: "active",
    });
  });

  it("renders a description that is set", () => {
    expect(
      endpointSettingsFormValues(endpointView({ description: "Demo server" }))
        .description,
    ).toBe("Demo server");
  });
});

describe("endpointSettingsPatch", () => {
  it("is empty for a form nobody touched", () => {
    // An empty patch is accepted by the API and writes an `endpoint.updated` audit
    // event naming no fields, so the form must produce nothing to send.
    const current = endpointView();

    expect(
      endpointSettingsPatch(endpointSettingsFormValues(current), current),
    ).toEqual({});
  });

  it("is empty for a form nobody touched when the description is set", () => {
    // The round trip through "" and back to a string is where a naive comparison
    // reports a change that did not happen.
    const current = endpointView({ description: "Demo server" });

    expect(
      endpointSettingsPatch(endpointSettingsFormValues(current), current),
    ).toEqual({});
  });

  it("carries only the field that changed", () => {
    const current = endpointView();

    expect(
      endpointSettingsPatch(
        { ...endpointSettingsFormValues(current), name: "Pathling demo" },
        current,
      ),
    ).toEqual({ name: "Pathling demo" });
  });

  it("sends a cleared description as null rather than as an empty string", () => {
    const current = endpointView({ description: "Demo server" });

    expect(
      endpointSettingsPatch(
        { ...endpointSettingsFormValues(current), description: "" },
        current,
      ),
    ).toEqual({ description: null });
  });

  it("parses a changed lifetime into a number", () => {
    const current = endpointView();

    expect(
      endpointSettingsPatch(
        { ...endpointSettingsFormValues(current), accessTokenTtl: "1800" },
        current,
      ),
    ).toEqual({ accessTokenTtl: 1800 });
  });

  it("omits a lifetime that is not a positive integer", () => {
    // A half-typed or emptied lifetime must leave the field out of the patch
    // altogether. Carrying it as `undefined` would count as a change here and then
    // vanish in JSON.stringify, so Save would light up and send an empty body -
    // exactly the write this whole change exists to prevent.
    const current = endpointView();
    const values = endpointSettingsFormValues(current);

    for (const text of ["", "  ", "0", "-1", "12x", "1.5"]) {
      expect(
        endpointSettingsPatch({ ...values, accessTokenTtl: text }, current),
      ).toEqual({});
      expect(
        endpointSettingsPatch({ ...values, refreshTokenTtl: text }, current),
      ).toEqual({});
    }
  });

  it("carries a toggled production flag", () => {
    const current = endpointView();

    expect(
      endpointSettingsPatch(
        { ...endpointSettingsFormValues(current), isProduction: false },
        current,
      ),
    ).toEqual({ isProduction: false });
  });

  it("carries every changed field together", () => {
    const current = endpointView();

    expect(
      endpointSettingsPatch(
        {
          name: "Renamed",
          description: "Now described",
          fhirBaseUrl: "https://other.example.com/fhir",
          accessTokenTtl: "600",
          refreshTokenTtl: "3600",
          authMode: "persona",
          consentMode: "auto",
          isProduction: false,
          status: "disabled",
        },
        current,
      ),
    ).toEqual({
      name: "Renamed",
      description: "Now described",
      fhirBaseUrl: "https://other.example.com/fhir",
      accessTokenTtl: 600,
      refreshTokenTtl: 3600,
      authMode: "persona",
      consentMode: "auto",
      isProduction: false,
      status: "disabled",
    });
  });
});

describe("capabilityPatch", () => {
  it("is empty when no flag was toggled", () => {
    const capabilities = {
      supportsEhrLaunch: true,
      allowsPublicClients: false,
    };

    expect(capabilityPatch({ ...capabilities }, capabilities)).toEqual({});
  });

  it("carries only the flag that was toggled, at the top level", () => {
    // The patch schema takes each flag as a top-level key rather than a nested
    // record, so this is flat by construction.
    const capabilities = {
      supportsEhrLaunch: true,
      allowsPublicClients: false,
    };

    expect(
      capabilityPatch(
        { ...capabilities, allowsPublicClients: true },
        capabilities,
      ),
    ).toEqual({ allowsPublicClients: true });
  });

  it("carries a flag turned off", () => {
    // Withdrawing a published conformance claim is a change like any other, and
    // `false` must not be mistaken for "unset".
    expect(
      capabilityPatch(
        { supportsEhrLaunch: false },
        { supportsEhrLaunch: true },
      ),
    ).toEqual({ supportsEhrLaunch: false });
  });

  it("carries several toggled flags together", () => {
    const capabilities = {
      supportsEhrLaunch: true,
      allowsPublicClients: false,
      supportsOpenIdConnect: false,
    };

    expect(
      capabilityPatch(
        {
          supportsEhrLaunch: false,
          allowsPublicClients: true,
          supportsOpenIdConnect: false,
        },
        capabilities,
      ),
    ).toEqual({ supportsEhrLaunch: false, allowsPublicClients: true });
  });

  it("ignores a flag the form does not hold", () => {
    // The checkboxes are built from the loaded capabilities, so the two records
    // carry the same keys; a key present only in what was loaded is not a change.
    expect(
      capabilityPatch(
        { supportsEhrLaunch: true },
        { supportsEhrLaunch: true, allowsPublicClients: false },
      ),
    ).toEqual({});
  });
});
