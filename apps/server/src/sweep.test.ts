/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { sweepRecord } from "./sweep.js";

import type { SweepCounts } from "@signet/db";

/** A sweep that found something in two tables and nothing in the rest. */
const COUNTS: SweepCounts = {
  launchContexts: 3,
  authorizationCodes: 0,
  authorizationSessions: 0,
  accessTokens: 0,
  refreshTokens: 0,
  consents: 0,
  jtiReplay: 0,
  adminSessions: 0,
  endUserSessions: 0,
  passkeyChallenges: 11,
};

describe("sweepRecord", () => {
  it("reports every table's count under its own name", () => {
    // The whole point of the job is reclaiming space, so an operator has to be
    // able to read which table was actually growing out of the run's output.
    const record = sweepRecord(COUNTS);

    expect(record).toMatchObject({
      message: "signet.sweep.completed",
      launchContexts: 3,
      passkeyChallenges: 11,
      authorizationCodes: 0,
    });
  });

  it("totals the counts", () => {
    expect(sweepRecord(COUNTS)["deleted"]).toBe(14);
  });

  it("totals a table added later without being edited", () => {
    // Summed over the object rather than field by field, so a new runtime table
    // joining the sweep cannot be silently left out of the number an operator
    // reads. A hand-written sum is the shape that drifts.
    const withAnother = {
      ...COUNTS,
      somethingNew: 5,
    } as unknown as SweepCounts;

    expect(sweepRecord(withAnother)["deleted"]).toBe(19);
  });

  it("reports zero for a sweep that found nothing", () => {
    // A quiet run still reports. Silence is not an acceptable response to a job
    // having run, and zero is the answer that says the database was already clean
    // rather than that nothing happened.
    const empty = Object.fromEntries(
      Object.keys(COUNTS).map((key) => [key, 0]),
    ) as unknown as SweepCounts;

    expect(sweepRecord(empty)["deleted"]).toBe(0);
    expect(sweepRecord(empty)["message"]).toBe("signet.sweep.completed");
  });
});
