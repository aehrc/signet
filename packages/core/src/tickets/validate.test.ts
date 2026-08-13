/**
 * The pure half of a permission ticket exchange.
 *
 * Everything here is a judgement over claims whose signature the route has
 * already checked against the issuer's published keys. That division is what
 * makes each case below worth enumerating: the endpoint has to be able to tell an
 * app whose ticket expired apart from one whose ticket names a type this endpoint
 * does not accept, and a single opaque "invalid ticket" refusal would tell it
 * neither.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  PERMITTED_TICKET_ALGORITHMS,
  validatePermissionTicket,
} from "./validate.js";

/** The instant every temporal case is judged against. */
const NOW = new Date("2026-08-13T00:00:00Z");

/** The issuer the endpoint's ticket rule names. */
const ISSUER = "https://tickets.example.org";

/** The one ticket type the connectathon programme exercises. */
const ACCEPTED = ["patient-self-access"];

/** Seconds since the epoch, as a ticket claim carries them. */
function epoch(date: Date): number {
  return Math.floor(date.getTime() / 1000);
}

/** `NOW` shifted by some seconds. */
function shifted(seconds: number): Date {
  return new Date(NOW.getTime() + seconds * 1000);
}

/** A ticket's claims, with the case's overrides applied last. */
function ticketClaims(
  overrides: Readonly<Record<string, unknown>> = {},
): Record<string, unknown> {
  return {
    iss: ISSUER,
    jti: "ticket-1",
    iat: epoch(NOW),
    exp: epoch(shifted(300)),
    ticket_type: "patient-self-access",
    subject: {
      system: "http://ns.electronichealth.net.au/id/hi/ihi/1.0",
      value: "8003608500314687",
    },
    smart_scopes: ["patient/Patient.rs"],
    ...overrides,
  };
}

/** Validates a ticket with the case's overrides. */
function validate(
  overrides: Readonly<Record<string, unknown>> = {},
  acceptedTicketTypes: readonly string[] = ACCEPTED,
) {
  return validatePermissionTicket({
    claims: ticketClaims(overrides),
    issuer: ISSUER,
    acceptedTicketTypes,
    now: NOW,
  });
}

/** The refusal code a validation produced, or undefined when it succeeded. */
function refusalOf(result: { readonly ok: boolean } & Record<string, unknown>) {
  return result.ok ? undefined : result["code"];
}

describe("validatePermissionTicket", () => {
  it("accepts a ticket from the configured issuer within its validity", () => {
    const result = validate();

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.ticket.issuer).toBe(ISSUER);
      expect(result.ticket.ticketId).toBe("ticket-1");
      expect(result.ticket.ticketType).toBe("patient-self-access");
      expect(result.ticket.subject).toEqual({
        system: "http://ns.electronichealth.net.au/id/hi/ihi/1.0",
        value: "8003608500314687",
      });
      expect(result.ticket.issuedAt).toEqual(NOW);
      expect(result.ticket.expiresAt).toEqual(shifted(300));
      // Parsed through the same grammar the token endpoint parses a request's
      // scopes with, so the intersection compares like with like.
      expect(result.ticket.scopes).toEqual([
        {
          kind: "resource",
          context: "patient",
          resourceType: "Patient",
          permissions: ["r", "s"],
          parameters: [],
        },
      ]);
    }
  });

  it("refuses claims that are not an object", () => {
    expect(
      refusalOf(
        validatePermissionTicket({
          claims: "not-claims",
          issuer: ISSUER,
          acceptedTicketTypes: ACCEPTED,
          now: NOW,
        }),
      ),
    ).toBe("not-an-object");
  });

  it("refuses a ticket from an issuer that is not the configured one", () => {
    // The issuer is named by the endpoint's rule, not by the ticket: a ticket
    // that names somebody else is refused rather than trusted on its own say-so.
    expect(refusalOf(validate({ iss: "https://elsewhere.example.org" }))).toBe(
      "issuer-mismatch",
    );
    expect(refusalOf(validate({ iss: undefined }))).toBe("issuer-mismatch");
  });

  it("refuses a ticket with no identifier, since it could not be audited", () => {
    // The audit trail records the ticket's identifier and never the ticket. A
    // ticket with no `jti` leaves nothing to record.
    expect(refusalOf(validate({ jti: undefined }))).toBe("missing-ticket-id");
    expect(refusalOf(validate({ jti: "" }))).toBe("missing-ticket-id");
  });

  it("refuses a ticket with no issuance or expiry time", () => {
    expect(refusalOf(validate({ iat: undefined }))).toBe("missing-issued-at");
    expect(refusalOf(validate({ exp: undefined }))).toBe("missing-expiry");
    expect(refusalOf(validate({ exp: "soon" }))).toBe("missing-expiry");
  });

  it("refuses an expired ticket", () => {
    expect(refusalOf(validate({ exp: epoch(shifted(-1)) }))).toBe("expired");
  });

  it("refuses a ticket issued in the future beyond the clock tolerance", () => {
    // A minute of skew is tolerated, because two correct clocks disagree by
    // seconds; an hour is a ticket minted to become valid later.
    expect(refusalOf(validate({ iat: epoch(shifted(30)) }))).toBeUndefined();
    expect(refusalOf(validate({ iat: epoch(shifted(3600)) }))).toBe(
      "issued-in-the-future",
    );
  });

  it("refuses a ticket type the endpoint does not accept", () => {
    expect(refusalOf(validate({ ticket_type: "care-team-access" }))).toBe(
      "unsupported-ticket-type",
    );
    expect(refusalOf(validate({ ticket_type: undefined }))).toBe(
      "unsupported-ticket-type",
    );
  });

  it("refuses every ticket when the rule accepts no types at all", () => {
    // A rule naming no type grants nothing. The alternative reading - "all
    // types" - would make a half-configured endpoint accept types nobody chose.
    expect(refusalOf(validate({}, []))).toBe("unsupported-ticket-type");
  });

  it("refuses a ticket whose subject identifier is incomplete", () => {
    // Resolution is a search for `{system}|{value}`. Half of that pair is not a
    // narrower search, it is a different one.
    expect(refusalOf(validate({ subject: undefined }))).toBe("missing-subject");
    expect(
      refusalOf(validate({ subject: { value: "8003608500314687" } })),
    ).toBe("missing-subject");
    expect(refusalOf(validate({ subject: { system: "http://ns" } }))).toBe(
      "missing-subject",
    );
    expect(refusalOf(validate({ subject: "8003608500314687" }))).toBe(
      "missing-subject",
    );
  });

  it("refuses a ticket that constrains no scopes", () => {
    // The ticket is one of the three ceilings on the exchanged token. A ticket
    // with no scopes has no ceiling to contribute, and reading its silence as
    // "everything" is the mistake this whole grant exists to avoid.
    expect(refusalOf(validate({ smart_scopes: undefined }))).toBe(
      "missing-scopes",
    );
    expect(refusalOf(validate({ smart_scopes: [] }))).toBe("missing-scopes");
  });

  it("refuses a ticket whose scopes are not in the SMART grammar", () => {
    expect(refusalOf(validate({ smart_scopes: ["patient/Patient.zzz"] }))).toBe(
      "malformed-scope",
    );
    expect(refusalOf(validate({ smart_scopes: [42] }))).toBe("malformed-scope");
  });

  it("names ES256 among the algorithms a ticket may be signed with", () => {
    // The connectathon issuer signs with ES256; a permitted set excluding it
    // would refuse every ticket it ever mints. Closed rather than open: `none`
    // and the symmetric algorithms must never appear, because a ticket is
    // verified against a key its issuer publishes.
    expect(PERMITTED_TICKET_ALGORITHMS).toContain("ES256");
    expect(PERMITTED_TICKET_ALGORITHMS).not.toContain("none");
    expect(PERMITTED_TICKET_ALGORITHMS).not.toContain("HS256");
  });
});
