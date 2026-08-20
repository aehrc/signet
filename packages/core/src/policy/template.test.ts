/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  isTemplateFilterName,
  parseTemplate,
  renderTemplate,
  renderTemplateValue,
  TEMPLATE_FILTER_NAMES,
} from "./template.js";

import type { TemplateScope } from "./template.js";

const SCOPE: TemplateScope = {
  context: {
    patient: "Patient/123",
    encounter: "Encounter/456",
    needPatientBanner: false,
    fhirContext: [{ reference: "DiagnosticReport/1" }],
  },
  user: {
    id: "u1",
    fhirUser: "Practitioner/abc",
    displayName: null,
    roles: ["clinician", "admin"],
    attributes: { department: "Cardiology", level: 3 },
  },
  endpoint: {
    tenantSlug: "demo",
    slug: "pathling",
    issuer: "https://signet.example.org/t/demo/e/pathling",
    fhirBaseUrl: "https://fhir.example.org/fhir",
  },
  granted: ["patient/Observation.rs", "openid"],
  scope: {
    context: "patient",
    resourceType: "Observation",
    permissions: ["r", "s"],
    isWildcard: false,
    resourceTypeSuffix: ":Observation",
  },
  empty: [],
  flag: true,
  count: 7,
  nothing: null,
};

describe("parseTemplate", () => {
  it("returns a single literal segment for text with no interpolation", () => {
    expect(parseTemplate("plain text")).toEqual({
      segments: [{ kind: "literal", text: "plain text" }],
      unterminated: false,
    });
  });

  it("returns no segments for an empty template", () => {
    expect(parseTemplate("")).toEqual({ segments: [], unterminated: false });
  });

  it("splits literal and interpolated segments in order", () => {
    const parsed = parseTemplate("a{{ x }}b{{ y }}");
    expect(parsed.segments.map((segment) => segment.kind)).toEqual([
      "literal",
      "interpolation",
      "literal",
      "interpolation",
    ]);
  });

  it("parses a filter chain with arguments", () => {
    const parsed = parseTemplate("{{ granted | join:, | upper }}");
    expect(parsed.segments).toEqual([
      {
        kind: "interpolation",
        path: "granted",
        raw: " granted | join:, | upper ",
        filters: [{ name: "join", arg: "," }, { name: "upper" }],
      },
    ]);
  });

  it("preserves whitespace inside a quoted filter argument", () => {
    const parsed = parseTemplate('{{ granted | join:", " }}');
    const segment = parsed.segments[0];
    expect(segment?.kind === "interpolation" && segment.filters[0]).toEqual({
      name: "join",
      arg: ", ",
    });
  });

  it("flags an unterminated interpolation and keeps it as literal text", () => {
    const parsed = parseTemplate("a{{ x");
    expect(parsed.unterminated).toBe(true);
    expect(parsed.segments).toEqual([{ kind: "literal", text: "a{{ x" }]);
  });

  it("records an interpolation with no path", () => {
    const parsed = parseTemplate("{{ }}");
    const segment = parsed.segments[0];
    expect(segment?.kind === "interpolation" && segment.path).toBe("");
  });
});

describe("isTemplateFilterName", () => {
  it("recognises every documented filter", () => {
    for (const name of TEMPLATE_FILTER_NAMES) {
      expect(isTemplateFilterName(name)).toBe(true);
    }
  });

  it("rejects anything else", () => {
    for (const name of ["", "eval", "JOIN", "toString", "constructor"]) {
      expect(isTemplateFilterName(name)).toBe(false);
    }
  });
});

describe("renderTemplate - raw values", () => {
  it("returns the string a lone interpolation resolves to", () => {
    expect(renderTemplate("{{ context.patient }}", SCOPE)).toBe("Patient/123");
  });

  it("keeps an array an array", () => {
    expect(renderTemplate("{{ granted }}", SCOPE)).toEqual([
      "patient/Observation.rs",
      "openid",
    ]);
  });

  it("keeps a boolean a boolean, including false", () => {
    expect(renderTemplate("{{ context.needPatientBanner }}", SCOPE)).toBe(
      false,
    );
    expect(renderTemplate("{{ flag }}", SCOPE)).toBe(true);
  });

  it("keeps a number a number", () => {
    expect(renderTemplate("{{ count }}", SCOPE)).toBe(7);
  });

  it("keeps an object an object", () => {
    expect(renderTemplate("{{ user.attributes }}", SCOPE)).toEqual({
      department: "Cardiology",
      level: 3,
    });
  });

  it("keeps an empty array an empty array", () => {
    expect(renderTemplate("{{ empty }}", SCOPE)).toEqual([]);
  });

  it("tolerates surrounding whitespace in the interpolation", () => {
    expect(renderTemplate("{{context.patient}}", SCOPE)).toBe("Patient/123");
    expect(renderTemplate("{{    context.patient    }}", SCOPE)).toBe(
      "Patient/123",
    );
  });
});

describe("renderTemplate - string concatenation", () => {
  it("concatenates literal text around an interpolation", () => {
    expect(
      renderTemplate("pathling:read{{ scope.resourceTypeSuffix }}", SCOPE),
    ).toBe("pathling:read:Observation");
  });

  it("coerces a boolean in string position", () => {
    expect(
      renderTemplate("banner={{ context.needPatientBanner }}", SCOPE),
    ).toBe("banner=false");
  });

  it("coerces a number in string position", () => {
    expect(renderTemplate("n={{ count }}", SCOPE)).toBe("n=7");
  });

  it("joins an array with spaces in string position", () => {
    expect(renderTemplate("scopes: {{ granted }}", SCOPE)).toBe(
      "scopes: patient/Observation.rs openid",
    );
  });

  it("supports several interpolations in one template", () => {
    expect(
      renderTemplate("{{ endpoint.tenantSlug }}/{{ endpoint.slug }}", SCOPE),
    ).toBe("demo/pathling");
  });

  it("returns literal text unchanged", () => {
    expect(renderTemplate("pathling:search", SCOPE)).toBe("pathling:search");
    expect(renderTemplate("", SCOPE)).toBe("");
  });

  it("drops the whole template when one part is unresolvable", () => {
    // Emitting `Patient/undefined` would be worse than emitting nothing.
    expect(renderTemplate("ref={{ context.missing }}", SCOPE)).toBeUndefined();
  });

  it("keeps an unterminated interpolation as literal text", () => {
    expect(renderTemplate("a{{ x", SCOPE)).toBe("a{{ x");
  });
});

describe("renderTemplate - path resolution", () => {
  it("resolves a dotted path through nested objects", () => {
    expect(renderTemplate("{{ user.attributes.department }}", SCOPE)).toBe(
      "Cardiology",
    );
  });

  it("resolves an array index", () => {
    expect(renderTemplate("{{ granted.1 }}", SCOPE)).toBe("openid");
  });

  it("returns undefined for a missing root", () => {
    expect(renderTemplate("{{ nope }}", SCOPE)).toBeUndefined();
  });

  it("returns undefined for a missing leaf", () => {
    expect(renderTemplate("{{ context.missing }}", SCOPE)).toBeUndefined();
  });

  it("returns undefined when walking through a missing intermediate", () => {
    expect(renderTemplate("{{ nope.deeper.still }}", SCOPE)).toBeUndefined();
  });

  it("returns undefined when walking through a null intermediate", () => {
    expect(renderTemplate("{{ nothing.deeper }}", SCOPE)).toBeUndefined();
    expect(renderTemplate("{{ user.displayName.x }}", SCOPE)).toBeUndefined();
  });

  it("treats a resolved null as missing", () => {
    // A policy that means null writes a literal null; a template never produces
    // one by accident.
    expect(renderTemplate("{{ nothing }}", SCOPE)).toBeUndefined();
    expect(renderTemplate("{{ user.displayName }}", SCOPE)).toBeUndefined();
  });

  it("returns undefined for an empty path", () => {
    expect(renderTemplate("{{ }}", SCOPE)).toBeUndefined();
    expect(renderTemplate("{{ . }}", SCOPE)).toBeUndefined();
    expect(renderTemplate("{{ context. }}", SCOPE)).toBeUndefined();
  });

  it("refuses to walk the prototype chain", () => {
    for (const path of [
      "__proto__",
      "constructor",
      "user.constructor",
      "user.__proto__.x",
      "context.constructor.name",
      "user.roles.constructor",
    ]) {
      expect(renderTemplate(`{{ ${path} }}`, SCOPE)).toBeUndefined();
    }
  });

  it("does not expose inherited or built-in properties", () => {
    expect(renderTemplate("{{ user.toString }}", SCOPE)).toBeUndefined();
    expect(renderTemplate("{{ user.hasOwnProperty }}", SCOPE)).toBeUndefined();
  });

  it("does not reach into strings", () => {
    expect(
      renderTemplate("{{ context.patient.length }}", SCOPE),
    ).toBeUndefined();
  });

  it("evaluates nothing: an expression is just a failed path", () => {
    expect(renderTemplate("{{ 1 + 1 }}", SCOPE)).toBeUndefined();
    expect(renderTemplate("{{ count > 0 }}", SCOPE)).toBeUndefined();
  });
});

describe("renderTemplate - filters", () => {
  it("joins with a space by default", () => {
    expect(renderTemplate("{{ granted | join }}", SCOPE)).toBe(
      "patient/Observation.rs openid",
    );
  });

  it("joins with a given separator", () => {
    expect(renderTemplate("{{ granted | join:, }}", SCOPE)).toBe(
      "patient/Observation.rs,openid",
    );
    expect(renderTemplate('{{ granted | join:", " }}', SCOPE)).toBe(
      "patient/Observation.rs, openid",
    );
  });

  it("joins a non-array by coercing it", () => {
    expect(renderTemplate("{{ context.patient | join }}", SCOPE)).toBe(
      "Patient/123",
    );
  });

  it("joins nothing into undefined", () => {
    expect(renderTemplate("{{ missing | join }}", SCOPE)).toBeUndefined();
  });

  it("takes the first entry of an array", () => {
    expect(renderTemplate("{{ granted | first }}", SCOPE)).toBe(
      "patient/Observation.rs",
    );
  });

  it("takes the first entry of a non-array as itself", () => {
    expect(renderTemplate("{{ context.patient | first }}", SCOPE)).toBe(
      "Patient/123",
    );
  });

  it("returns undefined for the first entry of an empty array", () => {
    expect(renderTemplate("{{ empty | first }}", SCOPE)).toBeUndefined();
  });

  it("accepts a single-quoted filter argument", () => {
    expect(renderTemplate("{{ granted | join:';' }}", SCOPE)).toBe(
      "patient/Observation.rs;openid",
    );
  });

  it("substitutes an empty string for a default with no argument", () => {
    expect(renderTemplate("{{ missing | default }}", SCOPE)).toBe("");
  });

  it("does nothing for a stripPrefix with no argument", () => {
    expect(renderTemplate("{{ user.fhirUser | stripPrefix }}", SCOPE)).toBe(
      "Practitioner/abc",
    );
  });

  it("substitutes a default for a missing value", () => {
    expect(renderTemplate("{{ missing | default:none }}", SCOPE)).toBe("none");
    expect(renderTemplate("{{ nothing | default:none }}", SCOPE)).toBe("none");
    expect(renderTemplate("{{ empty | first | default:none }}", SCOPE)).toBe(
      "none",
    );
  });

  it("leaves a present value alone, including false", () => {
    expect(renderTemplate("{{ context.patient | default:none }}", SCOPE)).toBe(
      "Patient/123",
    );
    expect(
      renderTemplate("{{ context.needPatientBanner | default:true }}", SCOPE),
    ).toBe(false);
  });

  it("changes case", () => {
    expect(renderTemplate("{{ endpoint.slug | upper }}", SCOPE)).toBe(
      "PATHLING",
    );
    expect(
      renderTemplate("{{ user.attributes.department | lower }}", SCOPE),
    ).toBe("cardiology");
    expect(renderTemplate("{{ missing | upper }}", SCOPE)).toBeUndefined();
  });

  it("strips a prefix when present and leaves the value otherwise", () => {
    expect(
      renderTemplate("{{ user.fhirUser | stripPrefix:Practitioner/ }}", SCOPE),
    ).toBe("abc");
    expect(
      renderTemplate("{{ user.fhirUser | stripPrefix:Patient/ }}", SCOPE),
    ).toBe("Practitioner/abc");
    expect(
      renderTemplate("{{ missing | stripPrefix:Patient/ }}", SCOPE),
    ).toBeUndefined();
  });

  it("chains filters left to right", () => {
    expect(
      renderTemplate(
        "{{ granted | first | stripPrefix:patient/ | upper }}",
        SCOPE,
      ),
    ).toBe("OBSERVATION.RS");
  });

  it("resolves to undefined for an unknown filter", () => {
    expect(
      renderTemplate("{{ context.patient | explode }}", SCOPE),
    ).toBeUndefined();
    expect(renderTemplate("{{ context.patient | }}", SCOPE)).toBeUndefined();
  });

  it("does not let a later default mask an unknown filter", () => {
    // A typo must fail loudly by dropping the claim, not quietly emit a default.
    expect(
      renderTemplate("{{ context.patient | uppercase | default:x }}", SCOPE),
    ).toBeUndefined();
  });
});

describe("renderTemplate - value sanitisation", () => {
  it("drops values with no JSON form", () => {
    const scope: TemplateScope = {
      fn: () => "nope",
      sym: Symbol("s"),
      big: 10n,
      nan: Number.NaN,
      infinite: Number.POSITIVE_INFINITY,
    };
    for (const path of ["fn", "sym", "big", "nan", "infinite"]) {
      expect(renderTemplate(`{{ ${path} }}`, scope)).toBeUndefined();
      expect(renderTemplate(`x={{ ${path} }}`, scope)).toBeUndefined();
    }
  });

  it("strips unrepresentable entries out of an array", () => {
    const scope: TemplateScope = { values: ["a", () => "b", null, 2] };
    expect(renderTemplate("{{ values }}", scope)).toEqual(["a", 2]);
  });

  it("strips unrepresentable properties out of an object", () => {
    const scope: TemplateScope = {
      attributes: { a: "1", b: () => "2", c: null, d: false },
    };
    expect(renderTemplate("{{ attributes }}", scope)).toEqual({
      a: "1",
      d: false,
    });
  });

  it("does not copy a polluted prototype key into a claim", () => {
    const attributes = JSON.parse(
      '{"a":"1","__proto__":{"bad":true}}',
    ) as Record<string, unknown>;
    const rendered = renderTemplate("{{ attributes }}", { attributes });
    expect(rendered).toEqual({ a: "1" });
  });
});

describe("renderTemplateValue", () => {
  it("renders a string as a template", () => {
    expect(renderTemplateValue("{{ context.patient }}", SCOPE)).toBe(
      "Patient/123",
    );
  });

  it("passes literals through untouched", () => {
    expect(renderTemplateValue(true, SCOPE)).toBe(true);
    expect(renderTemplateValue(false, SCOPE)).toBe(false);
    expect(renderTemplateValue(42, SCOPE)).toBe(42);
    expect(renderTemplateValue(null, SCOPE)).toBeNull();
  });

  it("renders each entry of an array", () => {
    expect(
      renderTemplateValue(["{{ endpoint.slug }}", "literal"], SCOPE),
    ).toEqual(["pathling", "literal"]);
  });

  it("drops array entries that do not resolve", () => {
    expect(renderTemplateValue(["{{ missing }}", "kept"], SCOPE)).toEqual([
      "kept",
    ]);
  });

  it("renders object properties and drops those that do not resolve", () => {
    expect(
      renderTemplateValue(
        { patient: "{{ context.patient }}", other: "{{ missing }}", n: 1 },
        SCOPE,
      ),
    ).toEqual({ patient: "Patient/123", n: 1 });
  });

  it("renders nested structures", () => {
    expect(
      renderTemplateValue(
        { list: [{ ref: "{{ context.encounter }}" }] },
        SCOPE,
      ),
    ).toEqual({ list: [{ ref: "Encounter/456" }] });
  });

  it("returns undefined for an unresolvable top-level template", () => {
    expect(renderTemplateValue("{{ missing }}", SCOPE)).toBeUndefined();
  });
});
