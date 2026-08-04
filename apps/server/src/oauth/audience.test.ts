/**
 * Author: John Grimes
 */

import { describe, expect, it } from "vitest";

import { checkAudience } from "./audience.js";

const BASE = "https://fhir.example.org/R4";

describe("checkAudience", () => {
  it("accepts the exact base URL", () => {
    expect(checkAudience(BASE, BASE)).toEqual({ ok: true, audience: BASE });
  });

  it("accepts a trailing slash on either side", () => {
    expect(checkAudience(`${BASE}/`, BASE).ok).toBe(true);
    expect(checkAudience(BASE, `${BASE}/`).ok).toBe(true);
    expect(checkAudience(`${BASE}//`, BASE).ok).toBe(true);
  });

  it("refuses an absent value", () => {
    expect(checkAudience(undefined, BASE)).toEqual({
      ok: false,
      reason: "missing",
    });
    expect(checkAudience("", BASE)).toEqual({ ok: false, reason: "missing" });
  });

  it("refuses another server", () => {
    expect(checkAudience("https://fhir.attacker.example/R4", BASE)).toEqual({
      ok: false,
      reason: "mismatch",
    });
  });

  it("refuses a path prefix of the base URL", () => {
    expect(checkAudience("https://fhir.example.org", BASE).ok).toBe(false);
  });

  it("treats case as significant", () => {
    expect(checkAudience("https://fhir.example.org/r4", BASE).ok).toBe(false);
  });

  it("treats an explicit default port as significant", () => {
    expect(checkAudience("https://fhir.example.org:443/R4", BASE).ok).toBe(
      false,
    );
  });
});
