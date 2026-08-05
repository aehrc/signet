/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { END_USER_PAGES, isEndUserPagePath } from "./endUserPages.js";

describe("isEndUserPagePath", () => {
  it("recognises every page", () => {
    for (const page of END_USER_PAGES) {
      expect(isEndUserPagePath(`/t/demo/e/fhir/${page}`)).toBe(true);
    }
  });

  it("does not match the API beneath a page", () => {
    // `/manage` is a page; `/manage/session` is what the page calls. Serving the
    // shell for the second would hand a script HTML and a 200.
    expect(isEndUserPagePath("/t/demo/e/fhir/manage/session")).toBe(false);
    expect(isEndUserPagePath("/t/demo/e/fhir/apps/requests")).toBe(false);
  });

  it("does not match an OAuth endpoint", () => {
    expect(isEndUserPagePath("/t/demo/e/fhir/token")).toBe(false);
    expect(isEndUserPagePath("/t/demo/e/fhir/authorize")).toBe(false);
  });

  it("does not match a path outside an issuer", () => {
    expect(isEndUserPagePath("/console/login")).toBe(false);
    expect(isEndUserPagePath("/login")).toBe(false);
  });

  it("requires the issuer's shape", () => {
    expect(isEndUserPagePath("/x/demo/y/fhir/login")).toBe(false);
    expect(isEndUserPagePath("/t/demo/login")).toBe(false);
  });

  it("tolerates a trailing slash", () => {
    expect(isEndUserPagePath("/t/demo/e/fhir/login/")).toBe(true);
  });
});
