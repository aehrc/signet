import { describe, expect, it } from "vitest";

import { nextStepPath, pageForStep } from "./steps.js";

describe("pageForStep", () => {
  it("names the page for each rendered step", () => {
    expect(pageForStep("login")).toBe("/login");
    expect(pageForStep("select-context")).toBe("/picker");
    expect(pageForStep("consent")).toBe("/consent");
  });

  it("has no page for a step that leaves the browser", () => {
    // Both carry a redirect to the app instead.
    expect(pageForStep("complete")).toBeUndefined();
    expect(pageForStep("denied")).toBeUndefined();
  });
});

describe("nextStepPath", () => {
  const current = "/t/demo/e/fhir/login";

  it("stays put when the page already matches the step", () => {
    expect(nextStepPath(current, "login", "abc")).toBeUndefined();
  });

  it("moves to the picker when a context is needed", () => {
    expect(nextStepPath(current, "select-context", "abc")).toBe(
      "/t/demo/e/fhir/picker?session=abc",
    );
  });

  it("moves to consent from the picker", () => {
    expect(nextStepPath("/t/demo/e/fhir/picker", "consent", "abc")).toBe(
      "/t/demo/e/fhir/consent?session=abc",
    );
  });

  it("does not move for a step that has no page", () => {
    expect(nextStepPath(current, "complete", "abc")).toBeUndefined();
  });

  it("keeps the endpoint prefix it was given", () => {
    // No assumption about how the endpoint is addressed: the prefix is whatever
    // precedes the page segment.
    expect(nextStepPath("/t/other/e/second/login", "consent", "s")).toBe(
      "/t/other/e/second/consent?session=s",
    );
  });

  it("tolerates a trailing slash", () => {
    expect(
      nextStepPath("/t/demo/e/fhir/login/", "login", "abc"),
    ).toBeUndefined();
    expect(nextStepPath("/t/demo/e/fhir/login/", "consent", "abc")).toBe(
      "/t/demo/e/fhir/consent?session=abc",
    );
  });

  it("encodes the session identifier", () => {
    expect(nextStepPath(current, "consent", "a b")).toBe(
      "/t/demo/e/fhir/consent?session=a%20b",
    );
  });
});
