/**
 * Resolving a ticket's subject to exactly one patient.
 *
 * A permission ticket names its subject by identifier - an IHI, in the
 * connectathon programme - and the token Signet mints from it carries a patient
 * launch context. Everything between those two facts is one search against the
 * endpoint's own FHIR server, and the only answer that never guesses is exactly
 * one match. Zero and many are refusals, and they are *different* refusals: an
 * unknown subject is a data problem the caller can act on, and an ambiguous one
 * is a duplicate on the server that an operator has to fix.
 *
 * Exercised against a real FHIR stub on a real socket rather than a stubbed
 * `fetch`, for the reason the JWKS suite gives: that the outbound guard is in the
 * path is observable as a loopback address being refused, and a bare `fetch`
 * would succeed. The first test asserts that refusal without the flag, so the
 * flag is the thing being switched rather than the check being bypassed.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { searchPatientByIdentifier } from "./subjectResolution.js";
import { jsonResponse, startLocalListener } from "../test/localListener.js";

import type { LocalListener } from "../test/localListener.js";

/** The identifier system the connectathon programme's tickets use. */
const IHI_SYSTEM = "http://ns.electronichealth.net.au/id/hi/ihi/1.0";

/** The IHI the stub's patient carries. */
const IHI_VALUE = "8003608500314687";

/** A token the stub records but never verifies. */
const SYSTEM_TOKEN = "a.self.issued";

/** One `Bundle.entry` holding a Patient. */
function patientEntry(id: string): Record<string, unknown> {
  return { resource: { resourceType: "Patient", id } };
}

/** What one request the stub served looked like. */
interface ServedRequest {
  readonly pathname: string;
  readonly identifier: string | null;
  readonly count: string | null;
  readonly authorization: string | null;
}

/** A FHIR server answering one prepared response, recording what it was asked. */
async function startFhirStub(
  answer: (identifier: string | null) => Response,
): Promise<{
  readonly listener: LocalListener;
  readonly served: ServedRequest[];
}> {
  const served: ServedRequest[] = [];
  const listener = await startLocalListener(async (request) => {
    const url = new URL(request.url);
    served.push({
      pathname: url.pathname,
      identifier: url.searchParams.get("identifier"),
      count: url.searchParams.get("_count"),
      authorization: request.headers.get("authorization"),
    });
    return await Promise.resolve(answer(url.searchParams.get("identifier")));
  });
  return { listener, served };
}

/** Searches the stub for the programme's IHI, permitting loopback. */
async function search(
  listener: LocalListener,
  overrides: {
    readonly system?: string;
    readonly value?: string;
    readonly allowPrivateAddresses?: boolean;
  } = {},
) {
  return await searchPatientByIdentifier({
    fhirBaseUrl: `${listener.origin}/fhir`,
    accessToken: SYSTEM_TOKEN,
    subject: {
      system: overrides.system ?? IHI_SYSTEM,
      value: overrides.value ?? IHI_VALUE,
    },
    allowPrivateAddresses: overrides.allowPrivateAddresses ?? true,
  });
}

/** A bundle matching only the programme's exact system and value. */
function exactMatchOnly(identifier: string | null): Response {
  return jsonResponse({
    resourceType: "Bundle",
    type: "searchset",
    entry:
      identifier === `${IHI_SYSTEM}|${IHI_VALUE}`
        ? [patientEntry("pat-1")]
        : [],
  });
}

describe("searchPatientByIdentifier", () => {
  it("goes through the outbound guard, which refuses a loopback FHIR server", async () => {
    // The same stub, the same search, without the flag the compose stack sets.
    // A resolver calling `fetch` directly would resolve the patient here.
    const { listener } = await startFhirStub(exactMatchOnly);
    try {
      const result = await search(listener, { allowPrivateAddresses: false });
      expect(result.ok).toBe(false);
      expect(result.ok ? undefined : result.reason).toBe("search-failed");
    } finally {
      await listener.close();
    }
  });

  it("searches the endpoint's own FHIR server for the ticket's identifier", async () => {
    const { listener, served } = await startFhirStub(exactMatchOnly);
    try {
      const result = await search(listener);

      expect(result.ok).toBe(true);
      expect(result.ok ? result.patientId : undefined).toBe("pat-1");
      // The audience the endpoint fronts, with the identifier as a
      // system-and-value token search - never a bare value, which would match
      // whatever else on the server happened to carry the same digits.
      expect(served[0]?.pathname).toBe("/fhir/Patient");
      expect(served[0]?.identifier).toBe(`${IHI_SYSTEM}|${IHI_VALUE}`);
    } finally {
      await listener.close();
    }
  });

  it("presents the self-issued system token as a bearer credential", async () => {
    // Every server Signet fronts is a secured one. An unauthenticated search
    // would work against nothing.
    const { listener, served } = await startFhirStub(exactMatchOnly);
    try {
      await search(listener);
      expect(served[0]?.authorization).toBe(`Bearer ${SYSTEM_TOKEN}`);
    } finally {
      await listener.close();
    }
  });

  it("refuses when no patient carries the identifier", async () => {
    const { listener } = await startFhirStub(() =>
      jsonResponse({ resourceType: "Bundle", type: "searchset", entry: [] }),
    );
    try {
      const result = await search(listener);
      expect(result.ok).toBe(false);
      expect(result.ok ? undefined : result.reason).toBe("subject-unknown");
    } finally {
      await listener.close();
    }
  });

  it("refuses a bundle with no entry array at all", async () => {
    // A search that matched nothing may omit `entry` entirely rather than
    // sending an empty one. Both mean the same thing, and both refuse.
    const { listener } = await startFhirStub(() =>
      jsonResponse({ resourceType: "Bundle", type: "searchset", total: 0 }),
    );
    try {
      const result = await search(listener);
      expect(result.ok ? undefined : result.reason).toBe("subject-unknown");
    } finally {
      await listener.close();
    }
  });

  it("refuses when more than one patient carries the identifier", async () => {
    // Two patients sharing an IHI is a duplicate on the server. Picking one
    // would mint a token against a guessed patient.
    const { listener } = await startFhirStub(() =>
      jsonResponse({
        resourceType: "Bundle",
        type: "searchset",
        entry: [patientEntry("pat-1"), patientEntry("pat-2")],
      }),
    );
    try {
      const result = await search(listener);
      expect(result.ok).toBe(false);
      expect(result.ok ? undefined : result.reason).toBe("subject-ambiguous");
    } finally {
      await listener.close();
    }
  });

  it("refuses a duplicate the server paginated out of the first page", async () => {
    // A server whose page size is one answers a two-patient duplicate with one
    // entry and a total of two. Counting entries alone reads that as a clean
    // single match and mints a token against a patient that was picked rather
    // than resolved - which is the one thing FR-014 forbids.
    const { listener } = await startFhirStub(() =>
      jsonResponse({
        resourceType: "Bundle",
        type: "searchset",
        total: 2,
        entry: [patientEntry("pat-1")],
      }),
    );
    try {
      const result = await search(listener);
      expect(result.ok).toBe(false);
      expect(result.ok ? undefined : result.reason).toBe("subject-ambiguous");
    } finally {
      await listener.close();
    }
  });

  it("asks for enough matches to see a duplicate", async () => {
    // The count that makes the check above possible on a server whose default
    // page size is one. Two is all it takes: a second match is a refusal, so
    // there is never a reason to transfer a third.
    const { listener, served } = await startFhirStub(exactMatchOnly);
    try {
      await search(listener);
      expect(served[0]?.count).toBe("2");
    } finally {
      await listener.close();
    }
  });

  it("never matches across identifier systems", async () => {
    // A ticket minted in a system the endpoint's patients are not identified in
    // produces no match. The system is opaque to Signet and is passed through
    // exactly, so the server is the one that decides - and it decides "none".
    const { listener } = await startFhirStub(exactMatchOnly);
    try {
      const result = await search(listener, {
        system: "http://example.org/other-ids",
      });
      expect(result.ok ? undefined : result.reason).toBe("subject-unknown");
    } finally {
      await listener.close();
    }
  });

  it("counts only the patients in the bundle, not the search-mode outcomes", async () => {
    // A FHIR server may add an OperationOutcome entry describing the search.
    // Counting it would turn one match into two and refuse a resolvable subject.
    const { listener } = await startFhirStub(() =>
      jsonResponse({
        resourceType: "Bundle",
        type: "searchset",
        entry: [
          patientEntry("pat-1"),
          {
            search: { mode: "outcome" },
            resource: { resourceType: "OperationOutcome", issue: [] },
          },
        ],
      }),
    );
    try {
      const result = await search(listener);
      expect(result.ok ? result.patientId : undefined).toBe("pat-1");
    } finally {
      await listener.close();
    }
  });

  it("fails the exchange when the FHIR server refuses the search", async () => {
    // Never a fallback. A server that would not answer has not told Signet the
    // subject is unknown; it has told it nothing.
    const { listener } = await startFhirStub(() =>
      jsonResponse({ resourceType: "OperationOutcome" }, 401),
    );
    try {
      const result = await search(listener);
      expect(result.ok).toBe(false);
      expect(result.ok ? undefined : result.reason).toBe("search-failed");
      expect(result.ok ? "" : result.description).toContain("401");
    } finally {
      await listener.close();
    }
  });

  it("refuses a response that is not a bundle", async () => {
    const { listener } = await startFhirStub(() =>
      jsonResponse({ resourceType: "Patient", id: "pat-1" }),
    );
    try {
      const result = await search(listener);
      expect(result.ok ? undefined : result.reason).toBe("not-a-bundle");
    } finally {
      await listener.close();
    }
  });

  it("refuses a matched patient carrying no id to put in the context", async () => {
    // A launch context names the patient by resource id. An entry without one
    // resolves to nothing a token could carry.
    const { listener } = await startFhirStub(() =>
      jsonResponse({
        resourceType: "Bundle",
        type: "searchset",
        entry: [{ resource: { resourceType: "Patient" } }],
      }),
    );
    try {
      const result = await search(listener);
      expect(result.ok ? undefined : result.reason).toBe("subject-unknown");
    } finally {
      await listener.close();
    }
  });
});
