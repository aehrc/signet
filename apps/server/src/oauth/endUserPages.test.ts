/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  END_USER_PAGES,
  isEndUserPagePath,
  isTenantPagePath,
  TENANT_PAGES,
} from "./endUserPages.js";

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
    expect(isEndUserPagePath("/t/demo/e/fhir/invitation/accept")).toBe(false);
  });

  it("does not serve an invitation page under an endpoint", () => {
    // Invitations belong to the tenant; see `isTenantPagePath`.
    expect(isEndUserPagePath("/t/demo/e/fhir/invitation")).toBe(false);
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

describe("isTenantPagePath", () => {
  it("recognises every page", () => {
    for (const page of TENANT_PAGES) {
      expect(isTenantPagePath(`/t/demo/${page}`)).toBe(true);
    }
  });

  it("serves the invitation page an invitation link points at", () => {
    expect(isTenantPagePath("/t/demo/invitation")).toBe(true);
    expect(isTenantPagePath("/t/demo/invitation/")).toBe(true);
  });

  it("does not match the API beneath a page", () => {
    expect(isTenantPagePath("/t/demo/invitation/details")).toBe(false);
    expect(isTenantPagePath("/t/demo/invitation/accept")).toBe(false);
  });

  it("does not match the tenant's other routes or an endpoint's pages", () => {
    expect(isTenantPagePath("/t/demo/branding")).toBe(false);
    expect(isTenantPagePath("/t/demo/logo")).toBe(false);
    expect(isTenantPagePath("/t/demo/e/fhir/login")).toBe(false);
    expect(isTenantPagePath("/x/demo/invitation")).toBe(false);
  });
});
