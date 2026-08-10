/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  describeCeremonyFailure,
  passkeyCountLabel,
  registrationBlockedReason,
} from "./passkeys.js";
import { ApiError } from "../api/errors.js";

/** A browser ceremony failure, which arrives as a `DOMException`-shaped error. */
function ceremonyError(name: string): Error {
  const error = new Error("the browser said no");
  error.name = name;
  return error;
}

describe("passkeyCountLabel", () => {
  it("counts against the limit, so the reader knows how much room is left", () => {
    expect(passkeyCountLabel(2)).toBe("2 of 10 passkeys");
  });

  it("says one passkey rather than one passkeys", () => {
    expect(passkeyCountLabel(1)).toBe("1 of 10 passkeys");
  });

  it("says none rather than zero of ten", () => {
    // The empty state explains what a passkey is; a count of zero beside it would
    // be a second, less useful way of saying the same thing.
    expect(passkeyCountLabel(0)).toBe("No passkeys yet");
  });
});

describe("registrationBlockedReason", () => {
  it("gives no reason below the limit", () => {
    expect(registrationBlockedReason(0)).toBeUndefined();
    expect(registrationBlockedReason(9)).toBeUndefined();
  });

  it("states the limit at the limit", () => {
    // The button is disabled, and a disabled control with no explanation is a
    // dead end: the reader has to be told what to do instead.
    const reason = registrationBlockedReason(10);
    expect(reason).toContain("10");
    expect(reason).toContain("Remove one");
  });
});

describe("describeCeremonyFailure", () => {
  it("reports a cancelled registration as not completed", () => {
    // The browser reports a dismissed prompt and a timeout identically, so the
    // message says what happened rather than guessing why.
    expect(
      describeCeremonyFailure(ceremonyError("NotAllowedError"), "registration"),
    ).toBe("Registration was not completed.");
  });

  it("reports a cancelled sign-in in its own words", () => {
    expect(
      describeCeremonyFailure(ceremonyError("NotAllowedError"), "sign-in"),
    ).toBe("Sign-in was not completed.");
  });

  it("explains an authenticator that is already registered", () => {
    // What `excludeCredentials` produces. Without this the reader sees a raw
    // "InvalidStateError" for the one refusal that is entirely expected.
    expect(
      describeCeremonyFailure(
        ceremonyError("InvalidStateError"),
        "registration",
      ),
    ).toContain("already");
  });

  it("passes a refusal from the server through in its own words", () => {
    // The server's messages are written for the operator - the cap, the wrong
    // password - and restating them here would be a second place to keep right.
    expect(
      describeCeremonyFailure(
        new ApiError(409, "conflict", "That is the limit"),
        "registration",
      ),
    ).toBe("That is the limit");
  });

  it("still says something for a failure it does not recognise", () => {
    expect(describeCeremonyFailure({}, "sign-in").length).toBeGreaterThan(0);
  });
});
