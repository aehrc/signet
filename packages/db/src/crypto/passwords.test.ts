/**
 * Author: John Grimes
 */

import { argon2id } from "hash-wasm";
import { describe, expect, it } from "vitest";

import { encodeBase64 } from "./encoding.js";
import { hashPassword, needsRehash, verifyPassword } from "./passwords.js";

/**
 * Mints a PHC string with chosen parameters, standing in for a hash written by
 * an older release or by another Argon2 implementation.
 */
async function phc(
  password: string,
  parameters: {
    memoryKib: number;
    iterations: number;
    parallelism: number;
    saltBytes?: number;
    hashBytes?: number;
    variant?: string;
    version?: number;
  },
): Promise<string> {
  const salt = crypto.getRandomValues(
    new Uint8Array(parameters.saltBytes ?? 16),
  );
  const hash = await argon2id({
    password,
    salt,
    iterations: parameters.iterations,
    parallelism: parameters.parallelism,
    memorySize: parameters.memoryKib,
    hashLength: parameters.hashBytes ?? 32,
    outputType: "binary",
  });

  return [
    "",
    parameters.variant ?? "argon2id",
    `v=${parameters.version ?? 19}`,
    `m=${parameters.memoryKib},t=${parameters.iterations},p=${parameters.parallelism}`,
    encodeBase64(salt),
    encodeBase64(hash),
  ].join("$");
}

describe("hashPassword", () => {
  it("produces a self-describing argon2id PHC string", async () => {
    const stored = await hashPassword("correct horse battery staple");
    // The parameters are visible in the stored value, which is what lets them be
    // raised later without invalidating existing accounts.
    expect(stored).toMatch(
      /^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/,
    );
  });

  it("salts each hash, so identical passwords do not collide", async () => {
    const first = await hashPassword("hunter2");
    const second = await hashPassword("hunter2");
    expect(first).not.toBe(second);
    await expect(verifyPassword("hunter2", first)).resolves.toBe(true);
    await expect(verifyPassword("hunter2", second)).resolves.toBe(true);
  });

  it("never embeds the password", async () => {
    const stored = await hashPassword("literalpassword");
    expect(stored).not.toContain("literalpassword");
  });
});

describe("verifyPassword", () => {
  it("accepts the right password", async () => {
    const stored = await hashPassword("s3cret-passphrase");
    await expect(verifyPassword("s3cret-passphrase", stored)).resolves.toBe(
      true,
    );
  });

  it("rejects the wrong password, including near misses", async () => {
    const stored = await hashPassword("s3cret-passphrase");
    await expect(verifyPassword("s3cret-passphras", stored)).resolves.toBe(
      false,
    );
    await expect(verifyPassword("S3cret-passphrase", stored)).resolves.toBe(
      false,
    );
    await expect(verifyPassword("", stored)).resolves.toBe(false);
  });

  it("handles unicode and very long passwords", async () => {
    const password = `pässwörd-${"x".repeat(500)}-🔐`;
    const stored = await hashPassword(password);
    await expect(verifyPassword(password, stored)).resolves.toBe(true);
    await expect(verifyPassword(`${password}!`, stored)).resolves.toBe(false);
  });

  it("reads the parameters out of the stored hash rather than assuming today's", async () => {
    // Deliberately weaker than the current defaults: an account created before a
    // parameter increase must still be able to log in.
    const legacy = await phc("legacy-password", {
      memoryKib: 4096,
      iterations: 1,
      parallelism: 1,
    });
    await expect(verifyPassword("legacy-password", legacy)).resolves.toBe(true);
    await expect(verifyPassword("wrong", legacy)).resolves.toBe(false);
  });

  it("honours a non-default salt and digest length", async () => {
    const stored = await phc("odd-sizes", {
      memoryKib: 8192,
      iterations: 2,
      parallelism: 1,
      saltBytes: 24,
      hashBytes: 64,
    });
    await expect(verifyPassword("odd-sizes", stored)).resolves.toBe(true);
  });

  it.each([
    ["empty", ""],
    ["not a PHC string", "hunter2"],
    ["a bare digest", "e0f7d2c1a9"],
    ["missing fields", "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA"],
    ["extra fields", "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA$extra"],
    ["a bcrypt hash", "$2b$12$abcdefghijklmnopqrstuv"],
    ["padded base64", "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA==$aGFzaGhhc2hoYQ"],
    [
      "a non-base64 salt",
      "$argon2id$v=19$m=19456,t=2,p=1$!!!!!!!!!!!!!!!!!!!!!!$aGFzaGhhc2hoYQ",
    ],
  ])("returns false rather than throwing on %s", async (_case, stored) => {
    await expect(verifyPassword("hunter2", stored)).resolves.toBe(false);
  });

  it("refuses a variant other than argon2id", async () => {
    // Honouring the variant named in the row would let an attacker with database
    // write access downgrade the function that checks a password.
    const downgraded = await phc("downgrade-me", {
      memoryKib: 19_456,
      iterations: 2,
      parallelism: 1,
      variant: "argon2i",
    });
    await expect(verifyPassword("downgrade-me", downgraded)).resolves.toBe(
      false,
    );
  });

  it("refuses a version other than 19", async () => {
    const wrongVersion = await phc("some-password", {
      memoryKib: 19_456,
      iterations: 2,
      parallelism: 1,
      version: 16,
    });
    await expect(verifyPassword("some-password", wrongVersion)).resolves.toBe(
      false,
    );
  });

  it("refuses a memory cost large enough to be a denial of service", async () => {
    // Four gibibytes: a single poisoned row must not be able to make every login
    // attempt against that account allocate it.
    const poisoned =
      "$argon2id$v=19$m=4194305,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGE";
    await expect(verifyPassword("hunter2", poisoned)).resolves.toBe(false);
  });

  it("refuses a cost so low the hash is not a hash", async () => {
    const trivial =
      "$argon2id$v=19$m=1,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGE";
    await expect(verifyPassword("hunter2", trivial)).resolves.toBe(false);
  });
});

describe("needsRehash", () => {
  it("leaves a hash at the current parameters alone", async () => {
    expect(needsRehash(await hashPassword("current"))).toBe(false);
  });

  it("asks for an upgrade when any cost parameter is below today's", async () => {
    expect(
      needsRehash(
        await phc("x", { memoryKib: 4096, iterations: 2, parallelism: 1 }),
      ),
    ).toBe(true);
    expect(
      needsRehash(
        await phc("x", { memoryKib: 19_456, iterations: 1, parallelism: 1 }),
      ),
    ).toBe(true);
  });

  it("asks for an upgrade when the salt or digest is shorter than today's", async () => {
    expect(
      needsRehash(
        await phc("x", {
          memoryKib: 19_456,
          iterations: 2,
          parallelism: 1,
          saltBytes: 8,
        }),
      ),
    ).toBe(true);
    expect(
      needsRehash(
        await phc("x", {
          memoryKib: 19_456,
          iterations: 2,
          parallelism: 1,
          hashBytes: 16,
        }),
      ),
    ).toBe(true);
  });

  it("never downgrades a hash that is stronger than today's", async () => {
    expect(
      needsRehash(
        await phc("x", { memoryKib: 65_536, iterations: 4, parallelism: 1 }),
      ),
    ).toBe(false);
  });

  it("asks for a replacement for anything it cannot parse", () => {
    expect(needsRehash("")).toBe(true);
    expect(needsRehash("hunter2")).toBe(true);
    expect(needsRehash("$2b$12$abcdefghijklmnopqrstuv")).toBe(true);
  });
});
