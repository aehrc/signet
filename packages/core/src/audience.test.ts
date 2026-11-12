/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { namesAudience, resolveAudience } from "./audience.js";

const API = "https://api.example.org/v1";
const FHIR = "https://fhir.example.org/R4";

describe("resolveAudience - SMART on FHIR endpoint", () => {
  it("requires aud", () => {
    expect(
      resolveAudience({ kind: "smart", audience: FHIR, resources: [] }),
    ).toEqual({ ok: false, reason: "missing" });
    expect(
      resolveAudience({
        kind: "smart",
        audience: FHIR,
        aud: "",
        resources: [],
      }),
    ).toEqual({ ok: false, reason: "missing" });
  });

  it("accepts aud naming the FHIR base URL, either side of a trailing slash", () => {
    expect(
      resolveAudience({
        kind: "smart",
        audience: FHIR,
        aud: `${FHIR}/`,
        resources: [],
      }),
    ).toEqual({ ok: true, audience: `${FHIR}/` });
  });

  it("refuses aud naming another server", () => {
    expect(
      resolveAudience({
        kind: "smart",
        audience: FHIR,
        aud: "https://elsewhere.test/fhir",
        resources: [],
      }),
    ).toEqual({ ok: false, reason: "mismatch" });
  });
});

describe("resolveAudience - OAuth endpoint", () => {
  it("falls back to the endpoint's audience when the client names none", () => {
    expect(
      resolveAudience({ kind: "oauth", audience: API, resources: [] }),
    ).toEqual({ ok: true, audience: API });
  });

  it("accepts aud and resource values naming the audience", () => {
    expect(
      resolveAudience({
        kind: "oauth",
        audience: API,
        aud: API,
        resources: [`${API}/`, API],
      }),
    ).toEqual({ ok: true, audience: API });
  });

  it("refuses an aud naming another API", () => {
    expect(
      resolveAudience({
        kind: "oauth",
        audience: API,
        aud: "https://other.example.org",
        resources: [],
      }),
    ).toEqual({ ok: false, reason: "mismatch" });
  });

  it("refuses when any one resource names another API", () => {
    expect(
      resolveAudience({
        kind: "oauth",
        audience: API,
        resources: [API, "https://other.example.org"],
      }),
    ).toEqual({ ok: false, reason: "mismatch" });
  });

  it("treats case as significant", () => {
    expect(
      resolveAudience({
        kind: "oauth",
        audience: API,
        resources: ["https://API.example.org/v1"],
      }),
    ).toEqual({ ok: false, reason: "mismatch" });
  });
});

describe("namesAudience", () => {
  it("refuses a path prefix of the audience", () => {
    expect(namesAudience("https://fhir.example.org", FHIR)).toBe(false);
  });

  it("treats an explicit default port as significant", () => {
    expect(namesAudience("https://fhir.example.org:443/R4", FHIR)).toBe(false);
  });

  it("accepts any number of trailing slashes on either side", () => {
    expect(namesAudience(`${FHIR}//`, FHIR)).toBe(true);
    expect(namesAudience(FHIR, `${FHIR}/`)).toBe(true);
  });
});
