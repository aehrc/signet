import { describe, expect, it } from "vitest";

import { generateHapiInterceptor } from "./hapiInterceptor.js";

const options = {
  issuer: "https://signet.test/t/demo/e/hapi",
  jwksUri: "https://signet.test/t/demo/e/hapi/jwks",
  audience: "https://hapi.test/fhir",
  endpointName: "HAPI demo",
};

describe("generateHapiInterceptor", () => {
  const source = generateHapiInterceptor(options);

  it("embeds the endpoint's issuer, keys and audience", () => {
    expect(source).toContain(
      `private static final String ISSUER = "${options.issuer}"`,
    );
    expect(source).toContain(
      `private static final String JWKS_URI = "${options.jwksUri}"`,
    );
    expect(source).toContain(
      `private static final String AUDIENCE = "${options.audience}"`,
    );
  });

  it("names the endpoint it was generated for", () => {
    expect(source).toContain('"HAPI demo" endpoint');
  });

  it("extends the interceptor HAPI expects", () => {
    expect(source).toContain(
      "public class SignetAuthorizationInterceptor extends AuthorizationInterceptor",
    );
    expect(source).toContain("public List<IAuthRule> buildRuleList(");
  });

  it("accepts only the algorithms Signet signs with", () => {
    expect(source).toContain("JWSAlgorithm.RS384, JWSAlgorithm.ES384");
  });

  it("ends every rule list with an explicit denial", () => {
    // Without this, a request matching no rule falls through to the server's own
    // default, which is the difference between a whitelist and a suggestion.
    expect(source).toContain(
      'rules.denyAll("Not permitted by the access token',
    );
    expect(source).toContain('denyAll("No valid access token was presented")');
  });

  it("refuses a scope carrying search parameters rather than widening it", () => {
    expect(source).toContain("theScope.indexOf('?') >= 0");
  });

  it("normalises the v1 scope spellings", () => {
    expect(source).toContain('if (suffix.equals("read"))');
    expect(source).toContain('return "cud";');
    expect(source).toContain('return "cruds";');
  });

  it("restricts a patient-context scope to the patient compartment", () => {
    expect(source).toContain('inCompartment("Patient", compartment)');
  });

  it("honours a chosen package and class name", () => {
    const custom = generateHapiInterceptor({
      ...options,
      packageName: "com.example.security",
      className: "MyInterceptor",
    });

    expect(custom.startsWith("package com.example.security;")).toBe(true);
    expect(custom).toContain("public class MyInterceptor extends");
    expect(custom).toContain("new MyInterceptor()");
  });

  it("escapes a value that would otherwise break the generated Java", () => {
    const awkward = generateHapiInterceptor({
      ...options,
      endpointName: 'Quote " and backslash \\ and newline\n',
    });

    expect(awkward).toContain(
      String.raw`Quote \" and backslash \\ and newline\n`,
    );
    // The generated source must still be one Java string literal per constant: a
    // raw newline here would produce a file that does not compile.
    expect(awkward).not.toContain('"Quote " and');
  });

  it("is deterministic, so regenerating produces no spurious diff", () => {
    expect(generateHapiInterceptor(options)).toBe(source);
  });
});
