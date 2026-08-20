/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  federatedUsername,
  mapUpstreamClaims,
  mergeClaims,
  readRoles,
} from "./claims.js";

describe("readRoles", () => {
  it("reads an array of roles", () => {
    expect(readRoles({ groups: ["clinician", "admin"] }, "groups")).toEqual([
      "clinician",
      "admin",
    ]);
  });

  it("reads a space-delimited string, as scope-modelled providers send", () => {
    expect(readRoles({ roles: "clinician admin" }, "roles")).toEqual([
      "clinician",
      "admin",
    ]);
  });

  it("preserves order and drops duplicates and blanks", () => {
    expect(
      readRoles({ roles: ["b", "", "a", "b", "  ", " a "] }, "roles"),
    ).toEqual(["b", "a"]);
  });

  it("yields nothing when no claim was named", () => {
    expect(readRoles({ roles: ["clinician"] }, undefined)).toEqual([]);
  });

  it("yields nothing for a claim of the wrong type", () => {
    expect(readRoles({ roles: 42 }, "roles")).toEqual([]);
    expect(readRoles({ roles: { a: 1 } }, "roles")).toEqual([]);
  });

  it("drops non-string entries from an array", () => {
    expect(readRoles({ roles: ["clinician", 7, null] }, "roles")).toEqual([
      "clinician",
    ]);
  });
});

describe("mapUpstreamClaims", () => {
  it("maps every configured field", () => {
    expect(
      mapUpstreamClaims(
        {
          fhirUser: "fhir_user",
          roles: "groups",
          displayName: "name",
          attributes: ["department", "npi"],
        },
        {
          fhir_user: "Practitioner/123",
          groups: ["clinician"],
          name: "Dr Example",
          department: "Cardiology",
          npi: 1_234_567_890,
          email: "someone@example.org",
        },
      ),
    ).toEqual({
      fhirUser: "Practitioner/123",
      displayName: "Dr Example",
      roles: ["clinician"],
      attributes: { department: "Cardiology", npi: 1_234_567_890 },
    });
  });

  it("copies only the attributes the operator named", () => {
    const mapped = mapUpstreamClaims(
      { attributes: ["department"] },
      { department: "Cardiology", ssn: "not-yours" },
    );
    // The rule that matters: an upstream provider can put anything in a token,
    // and an unnamed claim must not reach a policy template - and from there a
    // signed access token.
    expect(mapped.attributes).toEqual({ department: "Cardiology" });
  });

  it("omits an attribute the provider did not send", () => {
    const mapped = mapUpstreamClaims({ attributes: ["department"] }, {});
    expect("department" in mapped.attributes).toBe(false);
  });

  it("omits fhirUser rather than inventing an empty one", () => {
    const mapped = mapUpstreamClaims({ fhirUser: "fhir_user" }, {});
    expect("fhirUser" in mapped).toBe(false);
  });

  it("omits fhirUser when the claim is blank or the wrong type", () => {
    expect(
      "fhirUser" in mapUpstreamClaims({ fhirUser: "f" }, { f: "   " }),
    ).toBe(false);
    expect("fhirUser" in mapUpstreamClaims({ fhirUser: "f" }, { f: 42 })).toBe(
      false,
    );
  });

  it("trims a value the provider padded", () => {
    expect(
      mapUpstreamClaims({ fhirUser: "f" }, { f: " Practitioner/1 " }).fhirUser,
    ).toBe("Practitioner/1");
  });

  it("maps nothing when nothing was configured", () => {
    expect(mapUpstreamClaims({}, { fhir_user: "Practitioner/1" })).toEqual({
      roles: [],
      attributes: {},
    });
  });
});

describe("mergeClaims", () => {
  it("returns the ID token's claims when there is no userinfo", () => {
    expect(mergeClaims({ sub: "u1", name: "A" }, undefined)).toEqual({
      sub: "u1",
      name: "A",
    });
  });

  it("lets userinfo win, since it is the fresher document", () => {
    expect(
      mergeClaims({ sub: "u1", name: "Old" }, { name: "New", email: "e" }),
    ).toEqual({ sub: "u1", name: "New", email: "e" });
  });

  it("never lets userinfo rewrite the subject", () => {
    expect(mergeClaims({ sub: "u1" }, { sub: "somebody-else" })["sub"]).toBe(
      "u1",
    );
  });
});

describe("federatedUsername", () => {
  it("namespaces the subject by issuer", () => {
    expect(federatedUsername("https://idp.example.org", "123")).toBe(
      "https://idp.example.org#123",
    );
  });

  it("keeps two providers' identically-numbered users apart", () => {
    expect(federatedUsername("https://a.example.org", "1")).not.toBe(
      federatedUsername("https://b.example.org", "1"),
    );
  });
});
