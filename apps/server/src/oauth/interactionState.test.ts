/**
 * Author: John Grimes
 */

import { describe, expect, it } from "vitest";

import {
  contextRequirements,
  requirementsSatisfied,
} from "./contextRequirements.js";
import { consentRequired, decideStep } from "./interactionState.js";

import type { InteractionInputs } from "./interactionState.js";
import type { Scope } from "@signet/core";

/** Parses the scope shapes the tests need without importing the whole parser. */
const LAUNCH_PATIENT: Scope = { kind: "launch", resource: "patient" };
const LAUNCH_ENCOUNTER: Scope = { kind: "launch", resource: "encounter" };
const LAUNCH_BARE: Scope = { kind: "launch" };
const OPENID: Scope = { kind: "identity", name: "openid" };
const PATIENT_OBSERVATION: Scope = {
  kind: "resource",
  context: "patient",
  resourceType: "Observation",
  permissions: ["r", "s"],
  parameters: [],
};
const USER_OBSERVATION: Scope = {
  kind: "resource",
  context: "user",
  resourceType: "Observation",
  permissions: ["r", "s"],
  parameters: [],
};

describe("contextRequirements", () => {
  it("requires a patient for launch/patient", () => {
    expect(contextRequirements([LAUNCH_PATIENT])).toEqual({
      patient: true,
      encounter: false,
    });
  });

  it("requires a patient for a patient-context resource scope", () => {
    expect(contextRequirements([PATIENT_OBSERVATION]).patient).toBe(true);
  });

  it("requires an encounter for launch/encounter", () => {
    expect(contextRequirements([LAUNCH_ENCOUNTER])).toEqual({
      patient: false,
      encounter: true,
    });
  });

  it("requires nothing for user-context and identity scopes", () => {
    expect(
      contextRequirements([OPENID, USER_OBSERVATION, LAUNCH_BARE]),
    ).toEqual({ patient: false, encounter: false });
  });
});

describe("requirementsSatisfied", () => {
  const needsPatient = { patient: true, encounter: false };

  it("is satisfied when nothing is required", () => {
    expect(
      requirementsSatisfied({ patient: false, encounter: false }, null),
    ).toBe(true);
  });

  it("is unsatisfied when a required patient is absent", () => {
    expect(requirementsSatisfied(needsPatient, null)).toBe(false);
    expect(requirementsSatisfied(needsPatient, {})).toBe(false);
  });

  it("treats a blank patient as absent", () => {
    expect(requirementsSatisfied(needsPatient, { patient: "" })).toBe(false);
  });

  it("is satisfied by a resolved patient", () => {
    expect(requirementsSatisfied(needsPatient, { patient: "123" })).toBe(true);
  });

  it("requires both when both are required", () => {
    const both = { patient: true, encounter: true };
    expect(requirementsSatisfied(both, { patient: "1" })).toBe(false);
    expect(requirementsSatisfied(both, { patient: "1", encounter: "2" })).toBe(
      true,
    );
  });
});

const base: InteractionInputs = {
  authenticated: true,
  requirements: { patient: false, encounter: false },
  resolvedContext: null,
  consentGranted: false,
  consentMode: "always",
  hasStoredConsent: false,
};

describe("consentRequired", () => {
  it("is not required once granted in this session", () => {
    expect(consentRequired({ ...base, consentGranted: true })).toBe(false);
  });

  it("is never required in auto mode", () => {
    expect(consentRequired({ ...base, consentMode: "auto" })).toBe(false);
  });

  it("is always required in always mode, even with a stored consent", () => {
    expect(
      consentRequired({
        ...base,
        consentMode: "always",
        hasStoredConsent: true,
      }),
    ).toBe(true);
  });

  it("is skipped in remember mode when a stored consent covers the request", () => {
    expect(
      consentRequired({
        ...base,
        consentMode: "remember",
        hasStoredConsent: true,
      }),
    ).toBe(false);
    expect(
      consentRequired({
        ...base,
        consentMode: "remember",
        hasStoredConsent: false,
      }),
    ).toBe(true);
  });
});

describe("decideStep", () => {
  it("asks for login first, whatever else is outstanding", () => {
    expect(
      decideStep({
        ...base,
        authenticated: false,
        requirements: { patient: true, encounter: false },
      }),
    ).toBe("login");
  });

  it("asks for context before consent", () => {
    expect(
      decideStep({
        ...base,
        requirements: { patient: true, encounter: false },
      }),
    ).toBe("select-context");
  });

  it("asks for consent once context is resolved", () => {
    expect(
      decideStep({
        ...base,
        requirements: { patient: true, encounter: false },
        resolvedContext: { patient: "123" },
      }),
    ).toBe("consent");
  });

  it("completes when nothing is outstanding", () => {
    expect(decideStep({ ...base, consentMode: "auto" })).toBe("complete");
    expect(decideStep({ ...base, consentGranted: true })).toBe("complete");
  });

  it("completes an EHR launch whose context arrived with the handle", () => {
    expect(
      decideStep({
        ...base,
        requirements: { patient: true, encounter: true },
        resolvedContext: { patient: "123", encounter: "456" },
        consentMode: "auto",
      }),
    ).toBe("complete");
  });
});
