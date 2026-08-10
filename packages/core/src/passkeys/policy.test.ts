/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  counterAccepted,
  decidePasskeySignIn,
  MAX_PASSKEYS_PER_ACCOUNT,
  MAX_PASSKEY_NAME_LENGTH,
  passkeyCapReached,
  passkeyName,
  PASSKEY_CHALLENGE_TTL_SECONDS,
} from "./policy.js";

import type { PasskeySignInFacts } from "./policy.js";

/** A sign-in that every rule accepts, for a test to spoil one fact of. */
const ACCEPTED: PasskeySignInFacts = {
  credential: { counter: 4 },
  accountDisabled: false,
  userVerified: true,
  reportedCounter: 5,
};

describe("counterAccepted", () => {
  it("accepts a stored zero against a reported zero", () => {
    // The iCloud Keychain case. An authenticator that never counts reports zero
    // every time, and refusing that would lock out most platform authenticators.
    expect(counterAccepted(0, 0)).toBe(true);
  });

  it("accepts a counter that advanced", () => {
    expect(counterAccepted(7, 8)).toBe(true);
    expect(counterAccepted(0, 1)).toBe(true);
  });

  it("refuses a counter that stood still", () => {
    // The authenticator has counted before, so a repeat suggests a clone rather
    // than a device that does not count.
    expect(counterAccepted(7, 7)).toBe(false);
  });

  it("refuses a counter that went backwards", () => {
    expect(counterAccepted(7, 6)).toBe(false);
  });

  it("refuses a reported zero once a non-zero counter has been stored", () => {
    // The case a naive "reported >= stored is fine unless zero" rule gets wrong:
    // zero from an authenticator that has counted is a regression, not an
    // authenticator that does not count.
    expect(counterAccepted(7, 0)).toBe(false);
  });
});

describe("passkeyCapReached", () => {
  it("admits an account below the cap", () => {
    expect(passkeyCapReached(0)).toBe(false);
    expect(passkeyCapReached(MAX_PASSKEYS_PER_ACCOUNT - 1)).toBe(false);
  });

  it("refuses an account at the cap", () => {
    expect(passkeyCapReached(MAX_PASSKEYS_PER_ACCOUNT)).toBe(true);
  });

  it("refuses an account somehow past it", () => {
    // Defensive: the count comes from a query, and a rule written as equality
    // would admit an eleventh passkey to an account that already has eleven.
    expect(passkeyCapReached(MAX_PASSKEYS_PER_ACCOUNT + 1)).toBe(true);
  });

  it("caps at ten, which is what the API tells the caller", () => {
    expect(MAX_PASSKEYS_PER_ACCOUNT).toBe(10);
  });
});

describe("passkeyName", () => {
  it("keeps a supplied name, trimmed", () => {
    expect(passkeyName("  MacBook Touch ID  ", 0)).toBe("MacBook Touch ID");
  });

  it("numbers the default from what the account already holds", () => {
    // Distinct labels matter precisely in the list whose job is choosing which
    // passkey to remove, so blank submissions must not all collide.
    expect(passkeyName(null, 0)).toBe("Passkey 1");
    expect(passkeyName(undefined, 2)).toBe("Passkey 3");
  });

  it("treats a whitespace-only name as no name at all", () => {
    expect(passkeyName("   \t ", 1)).toBe("Passkey 2");
  });

  it("truncates a name longer than the column allows", () => {
    const long = "y".repeat(MAX_PASSKEY_NAME_LENGTH + 20);
    expect(passkeyName(long, 0)).toHaveLength(MAX_PASSKEY_NAME_LENGTH);
  });
});

describe("decidePasskeySignIn", () => {
  it("accepts a registered credential on a live account", () => {
    expect(decidePasskeySignIn(ACCEPTED)).toEqual({ ok: true });
  });

  it("accepts an authenticator that reports zero and has always reported zero", () => {
    expect(
      decidePasskeySignIn({
        ...ACCEPTED,
        credential: { counter: 0 },
        reportedCounter: 0,
      }),
    ).toEqual({ ok: true });
  });

  it("refuses a credential registered to nobody", () => {
    expect(decidePasskeySignIn({ ...ACCEPTED, credential: undefined })).toEqual(
      { ok: false, reason: "unknown-credential" },
    );
  });

  it("refuses a disabled account", () => {
    expect(decidePasskeySignIn({ ...ACCEPTED, accountDisabled: true })).toEqual(
      { ok: false, reason: "account-disabled" },
    );
  });

  it("refuses a ceremony completed without user verification", () => {
    // The passkey stands in for the second factor only because the authenticator
    // verified its user; without that it is one factor, and TOTP was skipped.
    expect(decidePasskeySignIn({ ...ACCEPTED, userVerified: false })).toEqual({
      ok: false,
      reason: "user-verification-missing",
    });
  });

  it("refuses a counter that did not advance", () => {
    expect(
      decidePasskeySignIn({
        ...ACCEPTED,
        credential: { counter: 5 },
        reportedCounter: 5,
      }),
    ).toEqual({ ok: false, reason: "counter-regressed" });
  });

  it("names an unknown credential before anything else", () => {
    // Order matters for the trail rather than for the caller: "no such
    // credential" is what an operator needs to see when every other fact is also
    // wrong, because the other facts belong to an account that was never reached.
    expect(
      decidePasskeySignIn({
        credential: undefined,
        accountDisabled: true,
        userVerified: false,
        reportedCounter: 0,
      }),
    ).toEqual({ ok: false, reason: "unknown-credential" });
  });
});

describe("the challenge window", () => {
  it("is five minutes", () => {
    // Long enough for a person to find their security key, short enough that an
    // unconsumed challenge is not a standing invitation.
    expect(PASSKEY_CHALLENGE_TTL_SECONDS).toBe(300);
  });
});
