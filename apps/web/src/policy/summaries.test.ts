/**
 * What a collapsed rule card says.
 *
 * A summary is the only thing an operator reads until they expand the card, so these
 * tests pin the exact wording: a summary that silently omitted a deny, a condition or
 * a context requirement would misrepresent what the policy does.
 *
 * Author: John Grimes
 */

import { describe, expect, test } from "bun:test";

import { summariseRule } from "./summaries.js";

import type {
  ClaimRule,
  ContextRule,
  ScopeGrantRule,
  ScopeMappingRule,
} from "@signet/core";

describe("summariseRule for scope grants", () => {
  test("states the decision and the pattern", () => {
    const rule: ScopeGrantRule = { match: "patient/*.rs", allow: true };
    expect(summariseRule("scopeGrants", rule)).toBe("Allow patient/*.rs");
  });

  test("a deny is named as one", () => {
    const rule: ScopeGrantRule = { match: "*/*.cud", allow: false };
    expect(summariseRule("scopeGrants", rule)).toBe("Deny */*.cud");
  });

  test("narrowing is mentioned, because it changes what an app receives", () => {
    const rule: ScopeGrantRule = {
      match: "patient/*.rs",
      allow: true,
      narrow: true,
    };
    expect(summariseRule("scopeGrants", rule)).toBe(
      "Allow patient/*.rs · narrows",
    );
  });

  test("a required launch context is mentioned", () => {
    const rule: ScopeGrantRule = {
      match: "patient/*.rs",
      allow: true,
      requireContext: ["patient"],
    };
    expect(summariseRule("scopeGrants", rule)).toBe(
      "Allow patient/*.rs · needs patient",
    );
  });

  test("multiple context requirements are listed together", () => {
    const rule: ScopeGrantRule = {
      match: "patient/*.rs",
      allow: true,
      requireContext: ["patient", "encounter"],
    };
    expect(summariseRule("scopeGrants", rule)).toBe(
      "Allow patient/*.rs · needs patient, encounter",
    );
  });

  test("grant type, client type and role restrictions are all visible", () => {
    const rule: ScopeGrantRule = {
      match: "system/*.rs",
      allow: true,
      grantTypes: ["client_credentials"],
      clientTypes: ["confidential-asymmetric"],
      requireUserRole: ["admin", "clinician"],
    };
    expect(summariseRule("scopeGrants", rule)).toBe(
      "Allow system/*.rs · client_credentials only · " +
        "confidential-asymmetric only · role admin or clinician",
    );
  });
});

describe("summariseRule for claim rules", () => {
  test("an unconditional rule lists what it emits", () => {
    const rule: ClaimRule = {
      when: { always: true },
      emit: { fhirUser: "{{ user.fhirUser }}", profile: "x" },
    };
    expect(summariseRule("claimRules", rule)).toBe(
      "Always → fhirUser, profile",
    );
  });

  test("a user-presence condition is described", () => {
    const rule: ClaimRule = {
      when: { hasUser: true },
      emit: { fhirUser: "{{ user.fhirUser }}" },
    };
    expect(summariseRule("claimRules", rule)).toBe(
      "When there is a user → fhirUser",
    );
  });

  test("a no-user condition is described", () => {
    const rule: ClaimRule = { when: { hasUser: false }, emit: { svc: "1" } };
    expect(summariseRule("claimRules", rule)).toBe(
      "When there is no user → svc",
    );
  });

  test("a scope condition shows its pattern", () => {
    const rule: ClaimRule = {
      when: { scope: "patient/*.rs" },
      emit: { patient_id: "{{ context.patient }}" },
    };
    expect(summariseRule("claimRules", rule)).toBe(
      "When a scope matches patient/*.rs → patient_id",
    );
  });

  test("a context condition lists its keys", () => {
    const rule: ClaimRule = {
      when: { context: ["patient", "encounter"] },
      emit: { enc: "{{ context.encounter }}" },
    };
    expect(summariseRule("claimRules", rule)).toBe(
      "When context has patient, encounter → enc",
    );
  });

  test("a condition the builder cannot represent is not guessed at", () => {
    // `grantTypes` is not one of the shapes the cards offer, so the summary must
    // not pretend the rule is simpler than it is.
    const rule: ClaimRule = {
      when: { hasUser: true, grantTypes: ["authorization_code"] },
      emit: { x: "y" },
    };
    expect(summariseRule("claimRules", rule)).toBe("Custom condition → x");
  });

  test("a rule emitting nothing says so", () => {
    const rule: ClaimRule = { when: { always: true }, emit: {} };
    expect(summariseRule("claimRules", rule)).toBe("Always → emits nothing");
  });
});

describe("summariseRule for context rules", () => {
  test("an absent condition reads as always", () => {
    const rule: ContextRule = {
      emit: { patient: "{{ context.patient }}", need_patient_banner: "n" },
    };
    expect(summariseRule("contextRules", rule)).toBe(
      "Always → patient, need_patient_banner",
    );
  });

  test("a present condition is described like a claim rule's", () => {
    const rule: ContextRule = {
      when: { context: ["encounter"] },
      emit: { encounter: "{{ context.encounter }}" },
    };
    expect(summariseRule("contextRules", rule)).toBe(
      "When context has encounter → encounter",
    );
  });
});

describe("summariseRule for scope mappings", () => {
  test("shows the pattern, the claim and how many values accumulate", () => {
    const rule: ScopeMappingRule = {
      forEachScope: "*/*.r",
      appendTo: "authorities",
      values: [
        "pathling:read{{ scope.resourceTypeSuffix }}",
        "pathling:search",
      ],
    };
    expect(summariseRule("scopeMappings", rule)).toBe(
      "*/*.r → authorities (2 values)",
    );
  });

  test("one value is counted in the singular", () => {
    const rule: ScopeMappingRule = {
      forEachScope: "*/*.c",
      appendTo: "authorities",
      values: ["pathling:import"],
    };
    expect(summariseRule("scopeMappings", rule)).toBe(
      "*/*.c → authorities (1 value)",
    );
  });
});
