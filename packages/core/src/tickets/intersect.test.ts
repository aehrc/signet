/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The three-way intersection, and the ceiling on how long its token may live.
 *
 * An exchanged token grants the overlap of three things: what the client asked
 * for, what the ticket permits, and what the endpoint's policy grants that
 * client. The first two are met here; the third is `evaluatePolicy`, which runs
 * over this function's result - so the last test in the intersection block
 * composes the two and asserts the property end to end, without a database or a
 * socket, which is the whole reason both halves are pure.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  capExchangedTokenLifetime,
  intersectTicketScopes,
} from "./intersect.js";
import { evaluatePolicy } from "../policy/evaluate.js";
import { SMART_BASELINE_PRESET } from "../policy/presets.js";
import { formatScopes, parseScopes } from "../scopes/index.js";

import type { EvaluationContext } from "../policy/types.js";
import type { Scope } from "../scopes/types.js";

/** Parses a space-delimited scope string, throwing on anything unparseable. */
function scopes(value: string): readonly Scope[] {
  const parsed = parseScopes(value);
  const rejected = parsed.rejected[0];
  if (rejected !== undefined) {
    throw new Error(`the fixture scope "${rejected.raw}" does not parse`);
  }
  return parsed.scopes;
}

/** The granted scopes of an intersection, as a canonical scope string. */
function granted(
  requested: string,
  ticket: string,
  allowlist = "patient/*.cruds user/*.cruds openid fhirUser offline_access",
): string | undefined {
  const result = intersectTicketScopes({
    requested: scopes(requested),
    ticketScopes: scopes(ticket),
    clientAllowlist: scopes(allowlist),
  });
  return result.ok ? formatScopes(result.scopes) : undefined;
}

/** An evaluation context with a patient resolved, as the exchange builds one. */
function exchangeContext(requested: readonly Scope[]): EvaluationContext {
  return {
    endpoint: {
      tenantSlug: "demo",
      slug: "fhir",
      issuer: "https://signet.test/t/demo/e/fhir",
      fhirBaseUrl: "https://fhir.test/R4",
    },
    client: {
      clientId: "app",
      name: "Ticket app",
      type: "confidential-symmetric",
      attributes: {},
    },
    user: null,
    requested,
    context: { patient: "pat-1" },
    grantType: "authorization_code",
  };
}

describe("intersectTicketScopes", () => {
  it("grants the scopes both the request and the ticket name", () => {
    expect(
      granted(
        "patient/Patient.rs patient/Observation.rs",
        "patient/Patient.rs",
      ),
    ).toBe("patient/Patient.rs");
  });

  it("grants the overlapping permissions rather than refusing the whole scope", () => {
    // An app that asks for everything and a ticket that permits reading meet at
    // reading. Refusing outright would hand a correctly ticketed app no access
    // at all, which fails at its first API call rather than degrading.
    expect(granted("patient/Patient.cruds", "patient/Patient.rs")).toBe(
      "patient/Patient.rs",
    );
  });

  it("resolves a wildcard on either side to the concrete type the other names", () => {
    expect(granted("patient/*.rs", "patient/Patient.rs")).toBe(
      "patient/Patient.rs",
    );
    expect(granted("patient/Observation.r", "patient/*.rs")).toBe(
      "patient/Observation.r",
    );
  });

  it("keeps a search restriction named by either side, since it only narrows", () => {
    expect(
      granted(
        "patient/Observation.rs",
        "patient/Observation.rs?category=laboratory",
      ),
    ).toBe("patient/Observation.rs?category=laboratory");
  });

  it("does not cross access contexts", () => {
    // A ticket permitting patient-context reads says nothing about what the
    // client may read as a user or as a system.
    expect(granted("user/Patient.rs", "patient/Patient.rs")).toBeUndefined();
  });

  it("intersects non-resource scopes by exact equality", () => {
    expect(granted("openid fhirUser", "openid")).toBe("openid");
    expect(granted("launch/patient", "launch/encounter")).toBeUndefined();
  });

  it("bounds the result by the client's own allowlist as well", () => {
    // The allowlist is the per-client ceiling an operator edits. A ticket cannot
    // hand a client access its registration never permitted it to ask for.
    expect(
      granted(
        "patient/Patient.rs patient/Observation.rs",
        "patient/Patient.rs patient/Observation.rs",
        "patient/Observation.rs",
      ),
    ).toBe("patient/Observation.rs");
  });

  it("never grants a refresh scope, whatever the three sides say", () => {
    // No refresh token is issued for this grant: the ticket's remaining validity
    // is the ceiling, and a refresh token outliving it would be a way around it.
    expect(
      granted(
        "patient/Patient.rs offline_access",
        "patient/Patient.rs offline_access",
      ),
    ).toBe("patient/Patient.rs");
  });

  it("refuses an empty intersection rather than returning nothing to grant", () => {
    // A scopeless token is worse than a refusal: the app believes it was
    // authorised and discovers otherwise at its first request.
    const result = intersectTicketScopes({
      requested: scopes("patient/Observation.rs"),
      ticketScopes: scopes("patient/Patient.rs"),
      clientAllowlist: scopes("patient/*.cruds"),
    });
    expect(result.ok).toBe(false);
    expect(result.ok ? undefined : result.code).toBe("no-overlap");
  });

  it("refuses a request that names no scopes at all", () => {
    const result = intersectTicketScopes({
      requested: [],
      ticketScopes: scopes("patient/Patient.rs"),
      clientAllowlist: scopes("patient/*.cruds"),
    });
    expect(result.ok).toBe(false);
    expect(result.ok ? undefined : result.code).toBe("nothing-requested");
  });

  it("composes with the policy to make the granted set a three-way intersection", () => {
    // The third side. What the ticket and the request agree on is what the
    // policy is then asked for, so a scope the policy refuses is not granted
    // however clearly the ticket permitted it.
    const overlap = intersectTicketScopes({
      requested: scopes("patient/Patient.rs system/Patient.rs"),
      ticketScopes: scopes("patient/Patient.rs system/Patient.rs"),
      clientAllowlist: scopes("patient/*.cruds system/*.cruds"),
    });
    expect(overlap.ok).toBe(true);

    const evaluation = evaluatePolicy(
      SMART_BASELINE_PRESET,
      exchangeContext(overlap.ok ? overlap.scopes : []),
    );
    // The baseline preset restricts `system/` scopes to the client credentials
    // grant, so only the patient-context half survives all three.
    expect(formatScopes(evaluation.grantedScopes)).toBe("patient/Patient.rs");
  });
});

describe("capExchangedTokenLifetime", () => {
  it("takes the smallest of the ceilings it is given", () => {
    expect(
      capExchangedTokenLifetime({
        ticketRemainingSeconds: 120,
        ruleMaxLifetimeSeconds: 300,
      }),
    ).toBe(120);
    expect(
      capExchangedTokenLifetime({
        ticketRemainingSeconds: 3600,
        ruleMaxLifetimeSeconds: 300,
      }),
    ).toBe(300);
  });

  it("never returns a negative lifetime", () => {
    // A ticket that expired between validation and issuance yields zero, which
    // the caller refuses; a negative `expires_in` would be minted as a token
    // already expired and reported as though it were live.
    expect(
      capExchangedTokenLifetime({
        ticketRemainingSeconds: -30,
        ruleMaxLifetimeSeconds: 300,
      }),
    ).toBe(0);
  });
});
