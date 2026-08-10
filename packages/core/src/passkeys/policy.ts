/**
 * What Signet decides about a passkey, as arithmetic over plain data.
 *
 * The cryptography is not here and must not be: verifying an attestation object or
 * an assertion signature is `@simplewebauthn/server`'s job, in `apps/server`, and
 * this package holds no dependencies at all. What is here is everything Signet
 * decides *around* the signature - the rules a reviewer has to be able to read
 * without a database or a browser, and which the console and the server must agree
 * on by construction rather than by coincidence.
 *
 * Every rule refuses unless something admits it. A sign-in is accepted only when the
 * credential is registered, the account is live, the authenticator verified its
 * user, and the counter moved the way it must; each of those failing has its own
 * name, recorded in the audit trail and never told to the caller.
 *
 * Author: John Grimes
 */

/**
 * The most passkeys one console account may hold.
 *
 * A cap rather than no limit because the registration options carry every
 * registered credential id in `excludeCredentials`, and an unbounded list is a
 * response that grows with whatever an attacker holding a session can register. Ten
 * is comfortably more devices than a person administers from.
 */
export const MAX_PASSKEYS_PER_ACCOUNT = 10;

/**
 * How long a ceremony challenge stays valid, in seconds.
 *
 * Long enough for somebody to find the security key in another room, short enough
 * that an unconsumed challenge is not a standing invitation. Single use is what
 * actually prevents replay; this bounds how long a stolen-but-unused one is worth
 * anything.
 */
export const PASSKEY_CHALLENGE_TTL_SECONDS = 300;

/** Longest a passkey name may be, in characters. */
export const MAX_PASSKEY_NAME_LENGTH = 64;

/**
 * Whether an account already holds as many passkeys as it may.
 *
 * Written as "at least" rather than "equal to", so a count that has somehow passed
 * the cap still refuses rather than admitting one more.
 *
 * @param count - How many the account holds now.
 * @returns True when another one may not be registered.
 */
export function passkeyCapReached(count: number): boolean {
  return count >= MAX_PASSKEYS_PER_ACCOUNT;
}

/**
 * The name to store for a passkey.
 *
 * A name is what tells one authenticator from another in a list whose whole purpose
 * is deciding which one to remove, so a blank submission gets a number rather than a
 * shared label: ten passkeys all called "Passkey" would make the list useless
 * exactly when it matters.
 *
 * @param supplied - What the person typed, if anything.
 * @param existingCount - How many the account already holds, which numbers the
 *   default.
 * @returns The trimmed name, truncated to {@link MAX_PASSKEY_NAME_LENGTH}, or the
 *   numbered default when nothing usable was supplied.
 * @example
 * ```ts
 * passkeyName("  MacBook Touch ID ", 0); // "MacBook Touch ID"
 * passkeyName("   ", 2); // "Passkey 3"
 * ```
 */
export function passkeyName(
  supplied: string | null | undefined,
  existingCount: number,
): string {
  const trimmed = (supplied ?? "").trim();
  return trimmed.length === 0
    ? `Passkey ${String(existingCount + 1)}`
    : trimmed.slice(0, MAX_PASSKEY_NAME_LENGTH);
}

/**
 * Whether a reported signature counter may be accepted.
 *
 * WebAuthn §6.1.1: an authenticator that counts its signatures reveals a cloned
 * credential by reporting a counter that has not advanced. Authenticators that do
 * not count - iCloud Keychain and most platform authenticators - report zero every
 * time, so the rule applies only once a non-zero counter has been stored. A stored
 * zero therefore accepts anything, which is not a hole: nothing about that
 * credential ever carried the information the rule reads.
 *
 * @param stored - The last counter accepted for this credential.
 * @param reported - What the authenticator has just reported.
 * @returns True when the sign-in may proceed on the counter's evidence.
 * @example
 * ```ts
 * counterAccepted(0, 0); // true - an authenticator that does not count
 * counterAccepted(7, 8); // true - it advanced
 * counterAccepted(7, 7); // false - it did not, and it does count
 * ```
 */
export function counterAccepted(stored: number, reported: number): boolean {
  return stored === 0 || reported > stored;
}

/** Why a passkey sign-in was refused. For the audit trail, never for the caller. */
export type PasskeySignInRefusal =
  | "unknown-credential"
  | "account-disabled"
  | "user-verification-missing"
  | "counter-regressed";

/** Everything the sign-in decision is made from. */
export interface PasskeySignInFacts {
  /** The registered credential, or absent when the assertion names none. */
  readonly credential: { readonly counter: number } | undefined;
  /** Whether the account the credential belongs to is locked out. */
  readonly accountDisabled: boolean;
  /** Whether the authenticator reported verifying its user. */
  readonly userVerified: boolean;
  /** The counter the authenticator reported with this assertion. */
  readonly reportedCounter: number;
}

/** Accept, or refuse with a reason nobody outside the audit trail is told. */
export type PasskeySignInDecision =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: PasskeySignInRefusal };

/**
 * Decides whether a verified assertion may establish a session.
 *
 * Called once the signature has been checked, and answers the question the
 * signature does not: whether *this* credential, on *this* account, presented this
 * way, is one Signet accepts. Each refusal is named so the operator reading the
 * trail afterwards can tell a disabled account from a cloned authenticator; the
 * caller is told the same sentence either way.
 *
 * The order is the order the facts become knowable. An unregistered credential
 * names no account, so nothing after it would be about anybody in particular.
 *
 * @param facts - The credential, the account's state and what the ceremony
 *   reported.
 * @returns Acceptance, or the first rule that refused.
 * @example
 * ```ts
 * decidePasskeySignIn({
 *   credential: { counter: 4 },
 *   accountDisabled: false,
 *   userVerified: true,
 *   reportedCounter: 5,
 * }); // { ok: true }
 * ```
 */
export function decidePasskeySignIn(
  facts: PasskeySignInFacts,
): PasskeySignInDecision {
  if (facts.credential === undefined) {
    return { ok: false, reason: "unknown-credential" };
  }
  if (facts.accountDisabled) {
    return { ok: false, reason: "account-disabled" };
  }
  if (!facts.userVerified) {
    return { ok: false, reason: "user-verification-missing" };
  }
  if (!counterAccepted(facts.credential.counter, facts.reportedCounter)) {
    return { ok: false, reason: "counter-regressed" };
  }
  return { ok: true };
}
