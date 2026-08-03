import { describe, expect, it } from "vitest";

import {
  fhirContextEntryType,
  toTokenResponseContext,
  validateLaunchContext,
} from "./validate.js";

import type {
  FhirContextEntry,
  LaunchContext,
  LaunchContextErrorCode,
  LaunchContextIssue,
} from "./types.js";

/** Collects the error codes from a validation, for terse assertions. */
function codes(context: LaunchContext): readonly LaunchContextErrorCode[] {
  const result = validateLaunchContext(context);
  return result.ok ? [] : result.issues.map((found) => found.code);
}

/** Validates and asserts failure, returning the issues for inspection. */
function issuesOf(context: LaunchContext): readonly LaunchContextIssue[] {
  const result = validateLaunchContext(context);
  if (result.ok) {
    throw new Error("Expected the launch context to be rejected");
  }
  return result.issues;
}

/** Validates and asserts success, returning the accepted context. */
function acceptedContext(context: LaunchContext): LaunchContext {
  const result = validateLaunchContext(context);
  if (!result.ok) {
    throw new Error(
      `Expected the launch context to be accepted, got ${JSON.stringify(result.issues)}`,
    );
  }
  return result.context;
}

/** Wraps entries in a launch context. */
function withContext(...entries: readonly FhirContextEntry[]): LaunchContext {
  return { fhirContext: entries };
}

describe("validateLaunchContext", () => {
  it("accepts an empty context", () => {
    const result = validateLaunchContext({});

    expect(result.ok).toBe(true);
  });

  it("returns the context unchanged when valid", () => {
    const context: LaunchContext = {
      patient: "123",
      encounter: "abc-456",
      intent: "reconcile-medications",
      tenant: "acme",
      needPatientBanner: false,
      smartStyleUrl: "https://ehr.example.com/style/smart-v1.json",
      fhirContext: [{ reference: "DiagnosticReport/789" }],
    };

    expect(validateLaunchContext(context)).toEqual({ ok: true, context });
    expect(acceptedContext(context)).toBe(context);
  });

  it("reports every issue rather than stopping at the first", () => {
    const issues = issuesOf({
      patient: "bad id",
      encounter: "also bad",
      smartStyleUrl: "not-a-url",
      fhirContext: [{}, { reference: "nope" }],
    });

    expect(issues.map((found) => found.code)).toEqual([
      "invalid-patient-id",
      "invalid-encounter-id",
      "invalid-style-url",
      "empty-fhir-context-entry",
      "invalid-reference",
    ]);
  });

  it("gives every issue a non-empty message", () => {
    const issues = issuesOf({
      patient: "bad id",
      fhirContext: [{ canonical: "relative/thing" }],
    });

    expect(issues.every((found) => found.message.trim().length > 0)).toBe(true);
  });
});

describe("validateLaunchContext: patient and encounter ids", () => {
  it.each(["1", "a", "123", "abc-def.ghi", "A".repeat(64), "-", "."])(
    "accepts patient id %j",
    (patient) => {
      expect(codes({ patient })).toEqual([]);
    },
  );

  it.each([
    ["", "empty"],
    ["A".repeat(65), "too long"],
    ["Patient/123", "a whole reference"],
    ["has space", "whitespace"],
    ["under_score", "an underscore"],
    ["café", "a non-ASCII letter"],
    ["123\n", "a trailing newline"],
  ])("rejects patient id %j (%s)", (patient) => {
    expect(codes({ patient })).toEqual(["invalid-patient-id"]);
  });

  it.each(["1", "abc-def.ghi", "Z".repeat(64)])(
    "accepts encounter id %j",
    (encounter) => {
      expect(codes({ encounter })).toEqual([]);
    },
  );

  it.each(["", "Encounter/1", "b".repeat(65), "has space"])(
    "rejects encounter id %j",
    (encounter) => {
      expect(codes({ encounter })).toEqual(["invalid-encounter-id"]);
    },
  );

  it("reports patient and encounter independently", () => {
    expect(codes({ patient: "ok", encounter: "not ok" })).toEqual([
      "invalid-encounter-id",
    ]);
  });
});

describe("validateLaunchContext: smartStyleUrl", () => {
  it.each([
    "https://ehr.example.com/style.json",
    "http://localhost:8080/style.json",
    "HTTPS://EHR.EXAMPLE.COM/style.json",
    "https://ehr.example.com/style.json?v=2",
  ])("accepts style URL %j", (smartStyleUrl) => {
    expect(codes({ smartStyleUrl })).toEqual([]);
  });

  it.each([
    ["", "empty"],
    ["/style.json", "relative"],
    ["style.json", "bare"],
    ["//ehr.example.com/style.json", "protocol relative"],
    ["ftp://ehr.example.com/style.json", "non-http scheme"],
    ["file:///etc/passwd", "file scheme"],
    ["javascript:alert(1)", "javascript scheme"],
    ["data:application/json,{}", "data URI"],
    ["urn:uuid:8f2a1c2e-0000-4000-8000-000000000000", "a URN"],
    ["https://ehr.example.com/a b.json", "internal whitespace"],
    [" https://ehr.example.com/style.json", "leading whitespace"],
    ["https://ehr.example.com/style.json\n", "a trailing newline"],
    ["https:ehr.example.com/style.json", "no authority"],
    ["https://", "an empty authority"],
    ["https://ehr.example.com/<style>.json", "excluded punctuation"],
  ])("rejects style URL %j (%s)", (smartStyleUrl) => {
    expect(codes({ smartStyleUrl })).toEqual(["invalid-style-url"]);
  });
});

describe("validateLaunchContext: fhirContext entry forms", () => {
  it("rejects an entry with none of the three forms", () => {
    expect(codes(withContext({}))).toEqual(["empty-fhir-context-entry"]);
  });

  it("rejects an entry carrying only a type and role", () => {
    expect(
      codes(
        withContext({ type: "Observation", role: "https://example.com/r" }),
      ),
    ).toEqual(["empty-fhir-context-entry"]);
  });

  it.each<[string, FhirContextEntry]>([
    [
      "reference and canonical",
      {
        reference: "Questionnaire/1",
        canonical: "https://example.com/Questionnaire/q",
      },
    ],
    [
      "reference and identifier",
      { reference: "Questionnaire/1", identifier: { value: "q" } },
    ],
    [
      "canonical and identifier",
      {
        canonical: "https://example.com/Questionnaire/q",
        identifier: { value: "q" },
      },
    ],
    [
      "all three",
      {
        reference: "Questionnaire/1",
        canonical: "https://example.com/Questionnaire/q",
        identifier: { value: "q" },
      },
    ],
  ])("rejects an entry with %s as ambiguous", (_label, entry) => {
    expect(codes(withContext(entry))).toContain("ambiguous-fhir-context-entry");
  });

  it("still validates each form present on an ambiguous entry", () => {
    expect(
      codes(withContext({ reference: "nope", canonical: "also-nope" })),
    ).toEqual([
      "ambiguous-fhir-context-entry",
      "invalid-reference",
      "invalid-canonical",
    ]);
  });

  it("sets the index of each entry issue", () => {
    const issues = issuesOf(
      withContext(
        { reference: "Observation/1" },
        {},
        { identifier: { system: "", value: "" } },
      ),
    );

    expect(issues).toEqual([
      expect.objectContaining({ code: "empty-fhir-context-entry", index: 1 }),
      expect.objectContaining({ code: "invalid-identifier", index: 2 }),
    ]);
  });

  it("leaves the index unset on context-level issues", () => {
    expect(issuesOf({ patient: "no good" })[0]?.index).toBeUndefined();
  });

  it("accepts an empty fhirContext array", () => {
    expect(codes({ fhirContext: [] })).toEqual([]);
  });
});

describe("validateLaunchContext: references", () => {
  it.each([
    "DiagnosticReport/123",
    "Observation/a",
    "List/abc-def.123",
    "MedicationRequest/" + "9".repeat(64),
    "ImagingStudy/1.2.840.113619.2.55",
  ])("accepts reference %j", (reference) => {
    expect(codes(withContext({ reference }))).toEqual([]);
  });

  it.each([
    ["", "empty"],
    ["Observation", "no id"],
    ["Observation/", "empty id"],
    ["/123", "no type"],
    ["observation/123", "lower case type"],
    ["Observation123/1", "digits in the type"],
    ["Observation_Extra/1", "an underscore in the type"],
    ["Observation/1/_history/2", "a version suffix"],
    ["Observation/" + "9".repeat(65), "an over-long id"],
    ["Observation/a b", "whitespace in the id"],
    ["Observation/a_b", "an underscore in the id"],
    ["https://example.com/Observation/1", "an absolute URL"],
    ["Observation/1?x=1", "a query string"],
  ])("rejects reference %j (%s)", (reference) => {
    expect(codes(withContext({ reference }))).toContain("invalid-reference");
  });
});

describe("validateLaunchContext: canonicals", () => {
  it.each([
    "https://example.com/Questionnaire/bp",
    "http://example.com/Questionnaire/bp",
    "https://example.com/Questionnaire/bp|1.0.0",
    "http://hl7.org/fhir/StructureDefinition/Patient|4.0.1",
    "urn:uuid:8f2a1c2e-0000-4000-8000-000000000000",
    "urn:oid:1.2.3.4|2",
  ])("accepts canonical %j", (canonical) => {
    expect(codes(withContext({ canonical }))).toEqual([]);
  });

  it.each([
    ["", "empty"],
    ["Questionnaire/bp", "relative"],
    ["/Questionnaire/bp", "root relative"],
    ["//example.com/Questionnaire/bp", "protocol relative"],
    ["example.com/Questionnaire/bp", "scheme-less"],
    ["https://example.com/Questionnaire/bp|", "a trailing bar"],
    ["https://example.com/Questionnaire/bp|1|2", "two bars"],
    ["|1.0.0", "a version with no URL"],
    ["https://example.com/a b", "internal whitespace"],
    [" https://example.com/q", "leading whitespace"],
    ["1https://example.com/q", "an invalid scheme start"],
    ["urn:", "a scheme with nothing after it"],
    ["https:example.com/q", "an http URL with no authority"],
    ["https://example.com/q<uestionnaire>", "excluded punctuation"],
    ["https://example.com/`q`", "a backtick"],
  ])("rejects canonical %j (%s)", (canonical) => {
    expect(codes(withContext({ canonical }))).toContain("invalid-canonical");
  });
});

describe("validateLaunchContext: identifiers", () => {
  it("accepts an identifier with a system only", () => {
    expect(
      codes(withContext({ identifier: { system: "http://example.com/mrn" } })),
    ).toEqual([]);
  });

  it("accepts an identifier with a value only", () => {
    expect(codes(withContext({ identifier: { value: "12345" } }))).toEqual([]);
  });

  it("accepts an identifier with both, plus use and type", () => {
    expect(
      codes(
        withContext({
          identifier: {
            system: "http://example.com/mrn",
            value: "12345",
            use: "official",
            type: { text: "Medical record number" },
          },
        }),
      ),
    ).toEqual([]);
  });

  it("rejects an identifier with neither system nor value", () => {
    expect(codes(withContext({ identifier: { use: "official" } }))).toEqual([
      "invalid-identifier",
    ]);
  });

  it("treats empty strings as absent", () => {
    expect(
      codes(withContext({ identifier: { system: "", value: "" } })),
    ).toEqual(["invalid-identifier"]);
  });

  it("accepts a system that is not a URL, leaving that to FHIR validation", () => {
    expect(codes(withContext({ identifier: { system: "mrn" } }))).toEqual([]);
  });
});

describe("validateLaunchContext: top-level-only resource types", () => {
  it.each(["Patient", "Encounter"])(
    "rejects a %s reference with no role",
    (type) => {
      expect(codes(withContext({ reference: `${type}/123` }))).toEqual([
        "forbidden-fhir-context-type",
      ]);
    },
  );

  it.each(["Patient", "Encounter"])(
    "rejects a %s reference with an explicit launch role",
    (type) => {
      expect(
        codes(withContext({ reference: `${type}/123`, role: "launch" })),
      ).toEqual(["forbidden-fhir-context-type"]);
    },
  );

  it("rejects an empty role, which the spec forbids, as equivalent to launch", () => {
    expect(codes(withContext({ reference: "Patient/1", role: "" }))).toEqual([
      "forbidden-fhir-context-type",
    ]);
  });

  it.each(["Patient", "Encounter"])(
    "rejects a %s declared only by the type field",
    (type) => {
      expect(
        codes(withContext({ canonical: "https://example.com/thing", type })),
      ).toEqual(["forbidden-fhir-context-type"]);
    },
  );

  it("rejects a Patient identifier entry declared by type", () => {
    expect(
      codes(withContext({ identifier: { value: "12345" }, type: "Patient" })),
    ).toEqual(["forbidden-fhir-context-type"]);
  });

  it("catches a Patient reference mislabelled with a benign type", () => {
    expect(
      codes(withContext({ reference: "Patient/1", type: "Observation" })),
    ).toEqual(["forbidden-fhir-context-type"]);
  });

  it("catches a benign reference mislabelled as a Patient", () => {
    expect(
      codes(withContext({ reference: "Observation/1", type: "Patient" })),
    ).toEqual(["forbidden-fhir-context-type"]);
  });

  it("reports both candidate types when each is forbidden", () => {
    expect(
      codes(withContext({ reference: "Patient/1", type: "Encounter" })),
    ).toEqual(["forbidden-fhir-context-type", "forbidden-fhir-context-type"]);
  });

  it.each(["Patient", "Encounter"])(
    "permits a %s entry with a non-launch role",
    (type) => {
      expect(
        codes(
          withContext({
            reference: `${type}/123`,
            role: "https://example.org/fhir/context-role#subject",
          }),
        ),
      ).toEqual([]);
    },
  );

  it("does not treat a case-mismatched type as forbidden", () => {
    expect(
      codes(withContext({ canonical: "urn:oid:1.2", type: "patient" })),
    ).toEqual([]);
  });

  it("permits other resource types with the default role", () => {
    expect(
      codes(
        withContext(
          { reference: "DiagnosticReport/1" },
          { reference: "PatientList/1" },
          { reference: "EncounterHistory/1" },
        ),
      ),
    ).toEqual([]);
  });

  it("reports the forbidden type alongside other entry issues", () => {
    expect(
      codes(
        withContext({ reference: "Patient/1", identifier: { value: "x" } }),
      ),
    ).toEqual(["ambiguous-fhir-context-entry", "forbidden-fhir-context-type"]);
  });

  it("does not infer a forbidden type from a malformed reference prefix", () => {
    expect(codes(withContext({ reference: "patient/1" }))).toEqual([
      "invalid-reference",
    ]);
  });
});

describe("fhirContextEntryType", () => {
  it("prefers the explicit type", () => {
    expect(
      fhirContextEntryType({ reference: "Observation/1", type: "List" }),
    ).toBe("List");
  });

  it("falls back to the reference prefix", () => {
    expect(fhirContextEntryType({ reference: "DiagnosticReport/1" })).toBe(
      "DiagnosticReport",
    );
  });

  it("ignores an empty type", () => {
    expect(fhirContextEntryType({ reference: "Observation/1", type: "" })).toBe(
      "Observation",
    );
  });

  it("returns undefined for a canonical entry with no type", () => {
    expect(
      fhirContextEntryType({
        canonical: "https://example.com/Questionnaire/q",
      }),
    ).toBeUndefined();
  });

  it("returns undefined for an identifier entry with no type", () => {
    expect(
      fhirContextEntryType({ identifier: { value: "1" } }),
    ).toBeUndefined();
  });

  it("returns undefined for an empty entry", () => {
    expect(fhirContextEntryType({})).toBeUndefined();
  });

  it.each(["nope", "/1", "observation/1", "Observation1/1"])(
    "returns undefined for unrecognisable reference %j",
    (reference) => {
      expect(fhirContextEntryType({ reference })).toBeUndefined();
    },
  );

  it("returns the type of a versioned reference despite it being invalid", () => {
    expect(
      fhirContextEntryType({ reference: "Observation/1/_history/2" }),
    ).toBe("Observation");
  });
});

describe("toTokenResponseContext", () => {
  it("omits everything for an empty context", () => {
    expect(toTokenResponseContext({})).toEqual({});
  });

  it("renders every parameter under its wire name", () => {
    expect(
      toTokenResponseContext({
        patient: "123",
        encounter: "456",
        intent: "reconcile-medications",
        tenant: "acme",
        needPatientBanner: true,
        smartStyleUrl: "https://ehr.example.com/style.json",
        fhirContext: [{ reference: "List/1" }],
      }),
    ).toEqual({
      patient: "123",
      encounter: "456",
      fhirContext: [{ reference: "List/1" }],
      intent: "reconcile-medications",
      tenant: "acme",
      need_patient_banner: true,
      smart_style_url: "https://ehr.example.com/style.json",
    });
  });

  it("emits a false banner flag rather than dropping it", () => {
    const rendered = toTokenResponseContext({ needPatientBanner: false });

    expect(rendered).toEqual({ need_patient_banner: false });
    expect("need_patient_banner" in rendered).toBe(true);
  });

  it("never emits nulls or undefined values", () => {
    const rendered = toTokenResponseContext({ patient: "123" });

    expect(Object.keys(rendered)).toEqual(["patient"]);
    expect(Object.values(rendered).every((value) => value != null)).toBe(true);
  });

  it("omits an empty fhirContext array", () => {
    expect(toTokenResponseContext({ fhirContext: [] })).toEqual({});
  });

  it("preserves fhirContext order", () => {
    expect(
      toTokenResponseContext({
        fhirContext: [
          { reference: "List/1" },
          { reference: "List/2" },
          { reference: "List/3" },
        ],
      }).fhirContext,
    ).toEqual([
      { reference: "List/1" },
      { reference: "List/2" },
      { reference: "List/3" },
    ]);
  });

  it("serialises every entry property that is present", () => {
    const rendered = toTokenResponseContext({
      fhirContext: [
        {
          canonical: "https://example.com/Questionnaire/bp|1.0.0",
          type: "Questionnaire",
          role: "https://example.org/role#template",
        },
        {
          identifier: {
            system: "http://example.com/mrn",
            value: "12345",
            use: "official",
            type: { text: "MRN" },
          },
        },
      ],
    });

    expect(rendered.fhirContext).toEqual([
      {
        canonical: "https://example.com/Questionnaire/bp|1.0.0",
        type: "Questionnaire",
        role: "https://example.org/role#template",
      },
      {
        identifier: {
          system: "http://example.com/mrn",
          value: "12345",
          use: "official",
          type: { text: "MRN" },
        },
      },
    ]);
  });

  it("drops undefined entry and identifier properties", () => {
    // Cast because the type spine forbids explicit undefined, but JSON
    // deserialised from a policy store can still carry the keys.
    const loose = [
      { reference: "List/1", canonical: undefined, role: undefined },
      { identifier: { value: "1", system: undefined, use: undefined } },
    ] as unknown as readonly FhirContextEntry[];
    const rendered = toTokenResponseContext({ fhirContext: loose });
    const entries = rendered.fhirContext as readonly Record<string, unknown>[];

    expect(Object.keys(entries[0] ?? {})).toEqual(["reference"]);
    expect(Object.keys(entries[1] ?? {})).toEqual(["identifier"]);
    expect(Object.keys(entries[1]?.identifier ?? {})).toEqual(["value"]);
  });

  it("does not share entry objects with the input", () => {
    const entry = { reference: "List/1" };
    const rendered = toTokenResponseContext({ fhirContext: [entry] });
    const entries = rendered.fhirContext as readonly unknown[];

    expect(entries[0]).not.toBe(entry);
    expect(entries[0]).toEqual(entry);
  });

  it("renders an invalid context too, leaving rejection to validation", () => {
    expect(toTokenResponseContext({ patient: "not valid" })).toEqual({
      patient: "not valid",
    });
  });
});
