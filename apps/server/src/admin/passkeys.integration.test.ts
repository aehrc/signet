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

import { countAdminPasskeyChallenges } from "@signet/db";
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
import type { PublicKeyCredentialCreationOptionsJSON } from "@simplewebauthn/server";

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

  /** Asks for creation options with the correct password. */
  async function creationOptions(credential: {
    readonly cookie: string;
  }): Promise<PublicKeyCredentialCreationOptionsJSON> {
    return await adminJson<PublicKeyCredentialCreationOptionsJSON>(
      stack,
      "POST",
      OPTIONS_PATH,
      { credential, body: { password: TEST_PASSWORD } },
    );
  }

  /** Registers one passkey from a fresh authenticator, start to finish. */
  async function registerPasskey(
    credential: { readonly cookie: string },
    name?: string,
  ): Promise<{
    readonly authenticator: VirtualAuthenticator;
    readonly response: Response;
  }> {
    const options = await creationOptions(credential);
    const authenticator = await createVirtualAuthenticator({
      origin: TEST_PUBLIC_URL,
    });
    const attestation = await authenticator.register(options);
    const response = await adminRequest(stack, "POST", LIST_PATH, {
      credential,
      body: { name: name ?? null, response: attestation },
    });
    return { authenticator, response };
  }

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
