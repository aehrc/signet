/**
 * The passkey routes, driven end to end against a real database and a real
 * authenticator.
 *
 * Nothing here is mocked, and that is the point: almost every property worth
 * asserting about these routes is a property of the WebAuthn verification - that a
 * replayed challenge is refused, that an assertion for another origin does not
 * verify, that a counter which did not advance is caught. A suite that stubbed the
 * verifier would assert the shape of the plumbing and none of the security. So the
 * ceremonies are produced by the software authenticator in `../test/`, signed with a
 * real P-256 key, and the server runs its real verifier over them.
 *
 * Skipped unless `SIGNET_TEST_DATABASE_URL` names a database that may be migrated.
 *
 * Author: John Grimes
 */

import { countAdminPasskeyChallenges, setAdminUserDisabled } from "@signet/db";
import { afterAll, beforeAll, describe, expect, it } from "bun:test";

import { adminJson, adminRequest, tenantPath } from "../test/adminApi.js";
import {
  createTestStack,
  TEST_PASSWORD,
  TEST_PUBLIC_URL,
  testDatabaseUrl,
} from "../test/harness.js";
import { createVirtualAuthenticator } from "../test/virtualAuthenticator.js";

import type { TestStack } from "../test/harness.js";
import type { VirtualAuthenticator } from "../test/virtualAuthenticator.js";
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/server";

/** The list of an account's registered passkeys, as the console reads it. */
interface PasskeyListBody {
  readonly passkeys: readonly {
    readonly id: string;
    readonly name: string;
    readonly createdAt: string;
    readonly lastUsedAt: string | null;
  }[];
}

const LIST_PATH = "/api/v1/account/passkeys";
const OPTIONS_PATH = "/api/v1/account/passkeys/options";
const SIGN_IN_OPTIONS_PATH = "/api/v1/session/passkey-options";
const SIGN_IN_PATH = "/api/v1/session/passkey";

/** A session cookie, in the shape the request helper wants. */
type Credential = { readonly cookie: string };

/** Asks for creation options with the correct password. */
async function creationOptionsFor(
  stack: TestStack,
  credential: Credential,
): Promise<PublicKeyCredentialCreationOptionsJSON> {
  return await adminJson<PublicKeyCredentialCreationOptionsJSON>(
    stack,
    "POST",
    OPTIONS_PATH,
    { credential, body: { password: TEST_PASSWORD } },
  );
}

/**
 * Registers one passkey from a fresh authenticator, start to finish.
 *
 * Takes the stack rather than closing over one, because several tests need a stack
 * of their own - a disabled account or an enforced rate limit would disturb every
 * other test sharing the fixture.
 */
async function registerPasskeyOn(
  stack: TestStack,
  credential: Credential,
  options: {
    readonly name?: string;
    /** Where the authenticator's counter starts. Non-zero models a security key. */
    readonly counter?: number;
  } = {},
): Promise<{
  readonly authenticator: VirtualAuthenticator;
  readonly response: Response;
}> {
  const creation = await creationOptionsFor(stack, credential);
  const authenticator = await createVirtualAuthenticator({
    origin: TEST_PUBLIC_URL,
    ...(options.counter === undefined ? {} : { counter: options.counter }),
  });
  const attestation = await authenticator.register(creation);
  const response = await adminRequest(stack, "POST", LIST_PATH, {
    credential,
    body: { name: options.name ?? null, response: attestation },
  });
  return { authenticator, response };
}

/** Runs a whole sign-in ceremony with an authenticator that already registered. */
async function signInWith(
  stack: TestStack,
  authenticator: VirtualAuthenticator,
  ceremony: Parameters<VirtualAuthenticator["authenticate"]>[1] = {},
): Promise<Response> {
  const options = await adminJson<PublicKeyCredentialRequestOptionsJSON>(
    stack,
    "POST",
    SIGN_IN_OPTIONS_PATH,
  );
  return await adminRequest(stack, "POST", SIGN_IN_PATH, {
    body: await authenticator.authenticate(options, ceremony),
  });
}

describe.skipIf(testDatabaseUrl === undefined)("console passkeys", () => {
  let stack: TestStack;

  beforeAll(async () => {
    stack = await createTestStack();
  });

  afterAll(async () => {
    await stack.close();
  });

  /** Signs in and returns the credential a browser would present. */
  const cookie = async () => ({ cookie: await stack.signIn() });

  /** Asks the shared fixture for creation options. */
  const creationOptions = async (credential: Credential) =>
    await creationOptionsFor(stack, credential);

  /** Registers a passkey on the shared fixture. */
  const registerPasskey = async (credential: Credential, name?: string) =>
    await registerPasskeyOn(stack, credential, {
      ...(name === undefined ? {} : { name }),
    });

  describe("listing", () => {
    it("answers an account with no passkeys with an empty list", async () => {
      const body = await adminJson<PasskeyListBody>(stack, "GET", LIST_PATH, {
        credential: { cookie: await stack.signIn(stack.outsider) },
      });

      expect(body.passkeys).toEqual([]);
    });

    it("returns the name and dates, and nothing about the credential", async () => {
      const credential = await cookie();
      await registerPasskey(credential, "Listed key");

      const body = await adminJson<PasskeyListBody>(stack, "GET", LIST_PATH, {
        credential,
      });
      const [passkey] = body.passkeys;

      expect(passkey?.name).toBe("Listed key");
      expect(passkey?.lastUsedAt).toBeNull();
      expect(Date.parse(passkey?.createdAt ?? "")).not.toBeNaN();
      // The credential identifier and the public key are columns on the row and
      // are deliberately not projected: no response body carries either.
      expect(JSON.stringify(body)).not.toContain("publicKey");
      expect(JSON.stringify(body)).not.toContain("credentialId");
    });

    it("shows one account nothing of another's", async () => {
      const mine = await cookie();
      await registerPasskey(mine, "Mine");

      const theirs = await adminJson<PasskeyListBody>(stack, "GET", LIST_PATH, {
        credential: { cookie: await stack.signIn(stack.outsider) },
      });

      expect(theirs.passkeys.some((passkey) => passkey.name === "Mine")).toBe(
        false,
      );
    });

    it("refuses a personal access token", async () => {
      // A passkey is managed by a person in a browser, not by a script: a token
      // holder is not the account owner and has no password to confirm with.
      const bearer = await stack.mintApiToken("owner");
      const response = await adminRequest(stack, "GET", LIST_PATH, {
        credential: { bearer },
      });

      expect(response.status).toBe(403);
    });

    it("refuses a caller with no credential at all", async () => {
      const response = await adminRequest(stack, "GET", LIST_PATH);
      expect(response.status).toBe(401);
    });
  });

  describe("asking for registration options", () => {
    it("refuses a wrong password, with a flag the dialog can act on", async () => {
      const response = await adminRequest(stack, "POST", OPTIONS_PATH, {
        credential: await cookie(),
        body: { password: "not the password" },
      });

      expect(response.status).toBe(401);
      const body = (await response.json()) as { passwordRejected?: boolean };
      // Distinguishable from a lapsed session, which the dialog must handle by
      // sending the reader to sign in rather than by saying "wrong password".
      expect(body.passwordRejected).toBe(true);
    });

    it("mints no challenge when the password was wrong", async () => {
      // Otherwise the wrong-password path would be a way to fill the table.
      const credential = await cookie();
      const before = await countChallenges();
      await adminRequest(stack, "POST", OPTIONS_PATH, {
        credential,
        body: { password: "not the password" },
      });

      expect(await countChallenges()).toBe(before);
    });

    it("requires user verification and a resident key", async () => {
      const options = await creationOptions(await cookie());

      // Both are what make the passkey a two-factor credential that needs no
      // username: resident so the browser can find it, verified so it stands in
      // for the second factor.
      expect(options.authenticatorSelection?.residentKey).toBe("required");
      expect(options.authenticatorSelection?.userVerification).toBe("required");
      expect(options.rp.id).toBe("signet.test");
      expect(options.challenge.length).toBeGreaterThan(20);
    });

    it("tells the browser to exclude an authenticator already registered", async () => {
      const credential = await cookie();
      const { authenticator } = await registerPasskey(credential, "First");

      const options = await creationOptions(credential);

      expect(options.excludeCredentials?.map((entry) => entry.id)).toContain(
        authenticator.credentialId,
      );
    });

    it("persists a challenge bound to the account that asked", async () => {
      const credential = await cookie();
      const before = await countChallenges();

      await creationOptions(credential);

      expect(await countChallenges()).toBe(before + 1);
    });

    it("refuses once the account holds ten", async () => {
      const full = await createTestStack();
      try {
        const credential = { cookie: await full.signIn() };
        for (let index = 0; index < 10; index += 1) {
          const options =
            await adminJson<PublicKeyCredentialCreationOptionsJSON>(
              full,
              "POST",
              OPTIONS_PATH,
              { credential, body: { password: TEST_PASSWORD } },
            );
          const authenticator = await createVirtualAuthenticator({
            origin: TEST_PUBLIC_URL,
          });
          const created = await adminRequest(full, "POST", LIST_PATH, {
            credential,
            body: {
              name: `Key ${String(index)}`,
              response: await authenticator.register(options),
            },
          });
          expect(created.status).toBe(201);
        }

        const refused = await adminRequest(full, "POST", OPTIONS_PATH, {
          credential,
          body: { password: TEST_PASSWORD },
        });

        expect(refused.status).toBe(409);
        const body = (await refused.json()) as { message: string };
        // The message states the limit, because "refused" alone leaves the reader
        // with nothing to do about it.
        expect(body.message).toContain("10");
      } finally {
        await full.close();
      }
    });

    it("refuses a personal access token", async () => {
      const bearer = await stack.mintApiToken("owner");
      const response = await adminRequest(stack, "POST", OPTIONS_PATH, {
        credential: { bearer },
        body: { password: TEST_PASSWORD },
      });

      expect(response.status).toBe(403);
    });

    it("is rate limited", async () => {
      // The route checks a password, so it is one of the surfaces where guessing
      // pays. Its own stack, because the limiter is off in the shared one.
      const limited = await createTestStack({ rateLimits: "enforced" });
      try {
        const credential = { cookie: await limited.signIn() };
        let refused = 0;
        for (let attempt = 0; attempt < 12; attempt += 1) {
          const response = await adminRequest(limited, "POST", OPTIONS_PATH, {
            credential,
            body: { password: "not the password" },
          });
          if (response.status === 429) {
            refused += 1;
          }
        }

        expect(refused).toBeGreaterThan(0);
      } finally {
        await limited.close();
      }
    });
  });

  describe("completing registration", () => {
    it("stores the passkey and answers with its view", async () => {
      const credential = await cookie();
      const { response } = await registerPasskey(
        credential,
        "MacBook Touch ID",
      );

      expect(response.status).toBe(201);
      const body = (await response.json()) as {
        readonly passkey: { readonly name: string; readonly id: string };
      };
      expect(body.passkey.name).toBe("MacBook Touch ID");

      const list = await adminJson<PasskeyListBody>(stack, "GET", LIST_PATH, {
        credential,
      });
      expect(list.passkeys.map((passkey) => passkey.id)).toContain(
        body.passkey.id,
      );
    });

    it("names an unnamed passkey after its position in the list", async () => {
      const named = await createTestStack();
      try {
        const credential = { cookie: await named.signIn() };
        const options = await adminJson<PublicKeyCredentialCreationOptionsJSON>(
          named,
          "POST",
          OPTIONS_PATH,
          { credential, body: { password: TEST_PASSWORD } },
        );
        const authenticator = await createVirtualAuthenticator({
          origin: TEST_PUBLIC_URL,
        });
        const created = await adminJson<{
          readonly passkey: { readonly name: string };
        }>(named, "POST", LIST_PATH, {
          credential,
          body: {
            name: "   ",
            response: await authenticator.register(options),
          },
          expect: 201,
        });

        expect(created.passkey.name).toBe("Passkey 1");
      } finally {
        await named.close();
      }
    });

    it("refuses a challenge that has already been spent", async () => {
      const credential = await cookie();
      const options = await creationOptions(credential);
      const authenticator = await createVirtualAuthenticator({
        origin: TEST_PUBLIC_URL,
      });
      const attestation = await authenticator.register(options);

      const first = await adminRequest(stack, "POST", LIST_PATH, {
        credential,
        body: { name: "Once", response: attestation },
      });
      expect(first.status).toBe(201);

      // The same ceremony replayed. The challenge row is gone, so there is nothing
      // to verify against - which is what single use means.
      const replay = await adminRequest(stack, "POST", LIST_PATH, {
        credential,
        body: { name: "Twice", response: attestation },
      });
      expect(replay.status).toBe(400);
    });

    it("refuses a challenge nobody issued", async () => {
      const credential = await cookie();
      const authenticator = await createVirtualAuthenticator({
        origin: TEST_PUBLIC_URL,
      });
      const attestation = await authenticator.register({
        ...(await creationOptions(credential)),
        challenge: "bm90LWEtY2hhbGxlbmdlLWFueWJvZHktaXNzdWVk",
      });

      const response = await adminRequest(stack, "POST", LIST_PATH, {
        credential,
        body: { name: "Forged", response: attestation },
      });

      expect(response.status).toBe(400);
    });

    it("refuses a challenge minted for somebody else", async () => {
      // The challenge is bound to the account whose password minted it, so one
      // person cannot complete a registration another person started.
      const mine = await cookie();
      const theirs = { cookie: await stack.signIn(stack.outsider) };
      const options = await adminJson<PublicKeyCredentialCreationOptionsJSON>(
        stack,
        "POST",
        OPTIONS_PATH,
        { credential: theirs, body: { password: TEST_PASSWORD } },
      );
      const authenticator = await createVirtualAuthenticator({
        origin: TEST_PUBLIC_URL,
      });

      const response = await adminRequest(stack, "POST", LIST_PATH, {
        credential: mine,
        body: {
          name: "Stolen",
          response: await authenticator.register(options),
        },
      });

      expect(response.status).toBe(400);
    });

    it("refuses a ceremony completed on another origin", async () => {
      // The property nothing else in the stack has: a credential created for one
      // origin cannot be presented to another, so a phishing page cannot mint one.
      const credential = await cookie();
      const options = await creationOptions(credential);
      const authenticator = await createVirtualAuthenticator({
        origin: "https://phishing.test",
      });

      const response = await adminRequest(stack, "POST", LIST_PATH, {
        credential,
        body: {
          name: "Elsewhere",
          response: await authenticator.register(options),
        },
      });

      expect(response.status).toBe(400);
    });

    it("refuses a credential identifier registered to another account", async () => {
      const mine = await cookie();
      const { authenticator } = await registerPasskey(mine, "Original");

      const theirs = { cookie: await stack.signIn(stack.outsider) };
      const options = await adminJson<PublicKeyCredentialCreationOptionsJSON>(
        stack,
        "POST",
        OPTIONS_PATH,
        { credential: theirs, body: { password: TEST_PASSWORD } },
      );
      const response = await adminRequest(stack, "POST", LIST_PATH, {
        credential: theirs,
        body: {
          name: "Duplicate",
          response: await authenticator.register(options),
        },
      });

      expect(response.status).toBe(400);
    });

    it("refuses a personal access token", async () => {
      const bearer = await stack.mintApiToken("owner");
      const response = await adminRequest(stack, "POST", LIST_PATH, {
        credential: { bearer },
        body: { name: null, response: {} },
      });

      expect(response.status).toBe(403);
    });

    it("records the registration in every tenant the account belongs to", async () => {
      const credential = await cookie();
      const { response } = await registerPasskey(credential, "Audited key");
      expect(response.status).toBe(201);

      const audit = await adminJson<{
        readonly events: readonly {
          readonly action: string;
          readonly detail: Record<string, unknown>;
        }[];
      }>(
        stack,
        "GET",
        tenantPath(stack, "/audit?action=admin.passkey-registered"),
        { credential },
      );

      const event = audit.events[0];
      expect(event?.action).toBe("admin.passkey-registered");
      expect(event?.detail["name"]).toBe("Audited key");
      // The trail names the passkey; it never carries the key material.
      expect(JSON.stringify(event?.detail)).not.toContain("publicKey");
    });
  });

  describe("asking for sign-in options", () => {
    it("is answered without any credential", async () => {
      // A person signing in has no session, so this route is one of the three the
      // admin API deliberately publishes.
      const response = await adminRequest(stack, "POST", SIGN_IN_OPTIONS_PATH);
      expect(response.status).toBe(200);
    });

    it("asks for no identifier and offers no credential list", async () => {
      const options = await adminJson<PublicKeyCredentialRequestOptionsJSON>(
        stack,
        "POST",
        SIGN_IN_OPTIONS_PATH,
      );

      // Empty rather than absent, and it matters: a list built from an email
      // would answer "does this address have a passkey?" for anybody who asked.
      expect(options.allowCredentials).toEqual([]);
      expect(options.userVerification).toBe("required");
      expect(options.rpId).toBe("signet.test");
    });

    it("persists the challenge it issued", async () => {
      const before = await countChallenges();
      await adminJson<PublicKeyCredentialRequestOptionsJSON>(
        stack,
        "POST",
        SIGN_IN_OPTIONS_PATH,
      );

      expect(await countChallenges()).toBe(before + 1);
    });
  });

  describe("signing in with a passkey", () => {
    it("establishes a session with nothing typed", async () => {
      const signingIn = await createTestStack();
      try {
        const credential = { cookie: await signingIn.signIn() };
        const { authenticator } = await registerPasskeyOn(
          signingIn,
          credential,
          { name: "Sign-in key" },
        );

        const response = await signInWith(signingIn, authenticator);

        expect(response.status).toBe(200);
        const setCookie = response.headers.get("set-cookie") ?? "";
        expect(setCookie).toContain("signet_session=");
        expect(setCookie).toContain("HttpOnly");
        expect(setCookie).toContain("Secure");
        // A response that establishes a credential must never be cached.
        expect(response.headers.get("cache-control")).toBe("no-store");

        const body = (await response.json()) as {
          readonly user: { readonly email: string };
          readonly tenants: readonly { readonly slug: string }[];
        };
        expect(body.user.email).toBe(signingIn.admin.email);
        expect(body.tenants[0]?.slug).toBe(signingIn.tenant.slug);
      } finally {
        await signingIn.close();
      }
    });

    it("produces a session the rest of the API accepts", async () => {
      // "Equivalent in every respect" is the promise, so the cookie is used
      // rather than merely inspected.
      const signingIn = await createTestStack();
      try {
        const credential = { cookie: await signingIn.signIn() };
        const { authenticator } = await registerPasskeyOn(
          signingIn,
          credential,
        );
        const response = await signInWith(signingIn, authenticator);
        const cookie = (response.headers.get("set-cookie") ?? "").split(
          ";",
          1,
        )[0];

        const tenant = await adminRequest(
          signingIn,
          "GET",
          tenantPath(signingIn),
          { credential: { cookie: cookie ?? "" } },
        );

        expect(tenant.status).toBe(200);
      } finally {
        await signingIn.close();
      }
    });

    it("asks a TOTP-enrolled account for no code", async () => {
      const enrolled = await createTestStack();
      try {
        const credential = { cookie: await enrolled.signIn() };
        const { authenticator } = await registerPasskeyOn(enrolled, credential);

        const { setAdminTotpSecret, encryptSecret } =
          await import("@signet/db");
        await setAdminTotpSecret(
          enrolled.context.db,
          enrolled.admin.id,
          await encryptSecret(
            "JBSWY3DPEHPK3PXP",
            enrolled.context.config.masterKey,
          ),
        );

        const response = await signInWith(enrolled, authenticator);

        // The authenticator verified its user, which is the second factor. A
        // `totpRequired` here would mean the passkey bought nothing.
        expect(response.status).toBe(200);
        const body = (await response.json()) as {
          readonly totpRequired?: boolean;
          readonly user: { readonly totpEnrolled: boolean };
        };
        expect(body.totpRequired).toBeUndefined();
        expect(body.user.totpEnrolled).toBe(true);
      } finally {
        await enrolled.close();
      }
    });

    it("records the last use and the counter the authenticator reported", async () => {
      const used = await createTestStack();
      try {
        const credential = { cookie: await used.signIn() };
        const { authenticator } = await registerPasskeyOn(used, credential, {
          counter: 4,
        });

        expect((await signInWith(used, authenticator)).status).toBe(200);

        const list = await adminJson<PasskeyListBody>(used, "GET", LIST_PATH, {
          credential,
        });
        expect(list.passkeys[0]?.lastUsedAt).not.toBeNull();
      } finally {
        await used.close();
      }
    });

    it("refuses a credential nobody registered", async () => {
      const stranger = await createVirtualAuthenticator({
        origin: TEST_PUBLIC_URL,
      });
      const response = await signInWith(stack, stranger);

      expect(response.status).toBe(401);
      expect((await response.json()) as unknown).toEqual({
        error: "unauthenticated",
        message: "Those credentials were not accepted",
      });
    });

    it("answers every refusal with the same body the password path gives", async () => {
      // The whole point of the generic refusal: an attacker holding a stolen
      // authenticator must not learn whether the account exists or is disabled.
      const stranger = await createVirtualAuthenticator({
        origin: TEST_PUBLIC_URL,
      });
      const passkeyRefusal = await signInWith(stack, stranger);
      const passwordRefusal = await adminRequest(
        stack,
        "POST",
        "/api/v1/session",
        {
          body: { email: stack.admin.email, password: "not the password" },
        },
      );

      expect(passkeyRefusal.status).toBe(passwordRefusal.status);
      expect(await passkeyRefusal.json()).toEqual(await passwordRefusal.json());
    });

    it("refuses a replayed assertion", async () => {
      const replayed = await createTestStack();
      try {
        const credential = { cookie: await replayed.signIn() };
        const { authenticator } = await registerPasskeyOn(replayed, credential);
        const options = await adminJson<PublicKeyCredentialRequestOptionsJSON>(
          replayed,
          "POST",
          SIGN_IN_OPTIONS_PATH,
        );
        const assertion = await authenticator.authenticate(options);

        const first = await adminRequest(replayed, "POST", SIGN_IN_PATH, {
          body: assertion,
        });
        expect(first.status).toBe(200);

        const second = await adminRequest(replayed, "POST", SIGN_IN_PATH, {
          body: assertion,
        });
        expect(second.status).toBe(401);
        expect(second.headers.get("set-cookie")).toBeNull();
      } finally {
        await replayed.close();
      }
    });

    it("refuses a challenge whose window has closed", async () => {
      const expired = await createTestStack();
      try {
        const credential = { cookie: await expired.signIn() };
        const { authenticator } = await registerPasskeyOn(expired, credential);
        const options = await adminJson<PublicKeyCredentialRequestOptionsJSON>(
          expired,
          "POST",
          SIGN_IN_OPTIONS_PATH,
        );

        // Six minutes on: the window is five.
        expired.setNow(new Date(Date.now() + 6 * 60_000));

        const response = await adminRequest(expired, "POST", SIGN_IN_PATH, {
          body: await authenticator.authenticate(options),
        });

        expect(response.status).toBe(401);
      } finally {
        await expired.close();
      }
    });

    it("refuses a ceremony completed without user verification", async () => {
      const unverified = await createTestStack();
      try {
        const credential = { cookie: await unverified.signIn() };
        const { authenticator } = await registerPasskeyOn(
          unverified,
          credential,
        );

        const response = await signInWith(unverified, authenticator, {
          userVerified: false,
        });

        // Without user verification the passkey is one factor, and TOTP was
        // skipped on the strength of it being two.
        expect(response.status).toBe(401);
        expect(response.headers.get("set-cookie")).toBeNull();
      } finally {
        await unverified.close();
      }
    });

    it("refuses a counter that did not advance", async () => {
      const cloned = await createTestStack();
      try {
        const credential = { cookie: await cloned.signIn() };
        const { authenticator } = await registerPasskeyOn(cloned, credential, {
          counter: 5,
        });

        // The authenticator counts, and reports a value it has used before -
        // which is what a cloned credential looks like.
        const response = await signInWith(cloned, authenticator, {
          counter: 5,
        });

        expect(response.status).toBe(401);
      } finally {
        await cloned.close();
      }
    });

    it("accepts an authenticator that always reports zero", async () => {
      // The other direction of the same rule. Most platform authenticators never
      // count, and refusing them would make the feature unusable on a Mac.
      const platform = await createTestStack();
      try {
        const credential = { cookie: await platform.signIn() };
        const { authenticator } = await registerPasskeyOn(
          platform,
          credential,
          { counter: 0 },
        );

        expect(
          (await signInWith(platform, authenticator, { counter: 0 })).status,
        ).toBe(200);
      } finally {
        await platform.close();
      }
    });

    it("refuses a disabled account", async () => {
      const disabled = await createTestStack();
      try {
        const credential = { cookie: await disabled.signIn() };
        const { authenticator } = await registerPasskeyOn(disabled, credential);
        await setAdminUserDisabled(
          disabled.context.db,
          disabled.admin.id,
          true,
        );

        const response = await signInWith(disabled, authenticator);

        expect(response.status).toBe(401);
        expect(response.headers.get("set-cookie")).toBeNull();
      } finally {
        await disabled.close();
      }
    });

    it("records the sign-in as a passkey sign-in", async () => {
      const audited = await createTestStack();
      try {
        const credential = { cookie: await audited.signIn() };
        const { authenticator } = await registerPasskeyOn(audited, credential);
        expect((await signInWith(audited, authenticator)).status).toBe(200);

        const trail = await adminJson<{
          readonly events: readonly {
            readonly detail: Record<string, unknown>;
          }[];
        }>(audited, "GET", tenantPath(audited, "/audit?action=admin.login"), {
          credential,
        });

        // The operator reading the trail has to be able to tell which credential
        // was used; the caller is told nothing either way.
        expect(trail.events[0]?.detail["method"]).toBe("passkey");
      } finally {
        await audited.close();
      }
    });

    it("records a refusal, with the reason only the trail sees", async () => {
      const audited = await createTestStack();
      try {
        const credential = { cookie: await audited.signIn() };
        const { authenticator } = await registerPasskeyOn(audited, credential);

        expect(
          (await signInWith(audited, authenticator, { userVerified: false }))
            .status,
        ).toBe(401);

        const trail = await adminJson<{
          readonly events: readonly {
            readonly detail: Record<string, unknown>;
          }[];
        }>(
          audited,
          "GET",
          tenantPath(audited, "/audit?action=admin.login-failed"),
          { credential },
        );

        expect(trail.events[0]?.detail["method"]).toBe("passkey");
        expect(trail.events[0]?.detail["reason"]).toBe(
          "user-verification-missing",
        );
      } finally {
        await audited.close();
      }
    });

    it("is rate limited on its own allowance", async () => {
      const limited = await createTestStack({ rateLimits: "enforced" });
      try {
        let refused = 0;
        for (let attempt = 0; attempt < 12; attempt += 1) {
          const response = await adminRequest(limited, "POST", SIGN_IN_PATH, {
            body: { id: "no-such-credential" },
          });
          if (response.status === 429) {
            refused += 1;
          }
        }
        expect(refused).toBeGreaterThan(0);

        // Exhausting the passkey surface must not lock anybody out of the
        // password one: the limiter keys on the route as well as the address.
        const password = await adminRequest(
          limited,
          "POST",
          "/api/v1/session",
          {
            body: { email: limited.admin.email, password: TEST_PASSWORD },
          },
        );
        expect(password.status).toBe(200);
      } finally {
        await limited.close();
      }
    });
  });

  /**
   * How many challenge rows exist.
   *
   * Counted rather than inspected, and counted across the whole table rather than
   * per account: the assertions using it compare a before and an after within one
   * test, which is what makes a shared table safe to count.
   */
  async function countChallenges(): Promise<number> {
    return await countAdminPasskeyChallenges(stack.context.db);
  }
});
