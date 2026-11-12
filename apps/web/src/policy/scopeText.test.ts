/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { scopeText } from "./scopeText.js";

describe("scopeText", () => {
  it("writes a custom scope as the string that was requested", () => {
    // Every API scope on an OAuth endpoint is custom, so this is the simulator's
    // main refusal on one.
    expect(scopeText({ kind: "custom", value: "orders:write" })).toBe(
      "orders:write",
    );
  });

  it("writes a resource scope with its parameters", () => {
    expect(
      scopeText({
        kind: "resource",
        context: "patient",
        resourceType: "Observation",
        permissions: ["r", "s"],
        parameters: [{ name: "category", value: "laboratory" }],
      }),
    ).toBe("patient/Observation.rs?category=laboratory");
  });

  it("writes a launch scope with its role", () => {
    expect(
      scopeText({ kind: "launch", resource: "patient", role: "admin" }),
    ).toBe("launch/patient?role=admin");
  });

  it("writes an identity scope by name", () => {
    expect(scopeText({ kind: "identity", name: "openid" })).toBe("openid");
  });

  it("passes a string through", () => {
    expect(scopeText("openid")).toBe("openid");
  });

  it("shows anything it does not recognise as it arrived", () => {
    expect(scopeText({ kind: "mystery" })).toBe('{"kind":"mystery"}');
    expect(scopeText(null)).toBe("null");
  });
});
