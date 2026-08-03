import { describe, expect, it } from "vitest";

import {
  insertVariable,
  interpolation,
  TEMPLATE_FILTERS,
  TEMPLATE_VARIABLES,
  variablesInGroup,
} from "./variables.js";

describe("TEMPLATE_VARIABLES", () => {
  it("has no duplicate paths", () => {
    const paths = TEMPLATE_VARIABLES.map((variable) => variable.path);
    expect(new Set(paths).size).toBe(paths.length);
  });

  it("describes every variable", () => {
    for (const variable of TEMPLATE_VARIABLES) {
      expect(variable.description.length).toBeGreaterThan(10);
    }
  });

  it("includes the ones an operator reaches for first", () => {
    const paths = TEMPLATE_VARIABLES.map((variable) => variable.path);
    expect(paths).toContain("user.fhirUser");
    expect(paths).toContain("context.patient");
    expect(paths).toContain("granted");
    expect(paths).toContain("scope.resourceTypeSuffix");
  });
});

describe("TEMPLATE_FILTERS", () => {
  it("comes from the evaluator, so the list cannot drift", () => {
    expect(TEMPLATE_FILTERS).toContain("join");
    expect(TEMPLATE_FILTERS).toContain("stripPrefix");
  });
});

describe("interpolation", () => {
  it("wraps a path in the template delimiters", () => {
    expect(interpolation("user.fhirUser")).toBe("{{ user.fhirUser }}");
  });
});

describe("insertVariable", () => {
  it("inserts at the caret", () => {
    expect(insertVariable("Patient/", "context.patient", 8)).toBe(
      "Patient/{{ context.patient }}",
    );
  });

  it("inserts at the start", () => {
    expect(insertVariable("/suffix", "context.patient", 0)).toBe(
      "{{ context.patient }}/suffix",
    );
  });

  it("clamps a caret beyond the value", () => {
    expect(insertVariable("abc", "granted", 99)).toBe("abc{{ granted }}");
  });

  it("clamps a negative caret", () => {
    expect(insertVariable("abc", "granted", -5)).toBe("{{ granted }}abc");
  });
});

describe("variablesInGroup", () => {
  it("returns only that group", () => {
    for (const variable of variablesInGroup("user")) {
      expect(variable.group).toBe("user");
    }
    expect(variablesInGroup("user").length).toBeGreaterThan(0);
  });
});
