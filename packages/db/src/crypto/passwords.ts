/**
 * Password hashing for console administrators and endpoint end users.
 *
 * Argon2id is the memory-hard function recommended by RFC 9106 for the
 * password-hashing case: the hybrid variant resists both the GPU-friendly
 * time-memory trade-off that argon2i concedes and the cache-timing side channel
 * that argon2d concedes.
 *
 * The implementation is `hash-wasm`, a WebAssembly build. That is a deployment
 * requirement, not a preference: the server ships as a single bundled file with
 * no `node_modules`, so a native addon such as `@node-rs/argon2` cannot be
 * loaded at all. WebAssembly bundles as inlined bytes and runs identically on
 * every architecture.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9106
 * @see https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
 *
 * Author: John Grimes
 */

import { argon2id } from "hash-wasm";

import { decodeBase64, encodeBase64 } from "./encoding.js";
import { timingSafeEqual } from "./tokens.js";

/**
 * The only Argon2 variant Signet issues or accepts.
 *
 * A stored hash naming `argon2i` or `argon2d` is rejected rather than verified:
 * honouring it would let a row rewritten by an attacker with database write
 * access downgrade the function used to check a password.
 */
const VARIANT = "argon2id";

/** Argon2 version 1.3, the only version RFC 9106 specifies. */
const VERSION = 19;

/**
 * Cost parameters for hashes minted today.
 *
 * 19 MiB of memory with two passes and no parallelism is the second of RFC 9106
 * section 4's recommended configurations, and OWASP's current minimum for
 * Argon2id. `p=1` is deliberate: the WebAssembly build has no threads, so a
 * higher degree of parallelism costs the defender the same wall-clock time it
 * costs an attacker with real threads - it would weaken the ratio, not improve
 * it. Raising `m` or `t` is the way to buy more resistance, and
 * {@link needsRehash} exists so that raising them upgrades existing accounts on
 * their next successful login.
 */
const CURRENT_PARAMETERS = {
  /** Memory cost in kibibytes. */
  memoryKib: 19_456,
  /** Number of passes over memory. */
  iterations: 2,
  /** Degree of parallelism. */
  parallelism: 1,
} as const;

/** Salt length in bytes; RFC 9106 section 4 recommends 16. */
const SALT_BYTES = 16;

/** Digest length in bytes; 256 bits, matching the rest of Signet. */
const HASH_BYTES = 32;

/**
 * Bounds on the parameters read out of a *stored* hash.
 *
 * `verifyPassword` has to honour whatever parameters a hash was minted with, but
 * it must not be turned into a weapon by them. Without an upper bound, a single
 * poisoned row - `m=4194304` - would make every login attempt against that
 * account allocate four gibibytes; without a lower bound, a hash minted at
 * trivial cost would be verified as though it were sound. Anything outside these
 * bounds is treated as a malformed hash: verification fails and
 * {@link needsRehash} asks for a replacement.
 */
const STORED_LIMITS = {
  minMemoryKib: 8,
  maxMemoryKib: 1_048_576,
  minIterations: 1,
  maxIterations: 16,
  minParallelism: 1,
  maxParallelism: 16,
  minSaltBytes: 8,
  maxSaltBytes: 64,
  minHashBytes: 16,
  maxHashBytes: 64,
} as const;

/**
 * The five fields of a PHC string: variant, version, `m,t,p`, salt, digest.
 *
 * Matched as a whole rather than split on `$`, so a value with extra or
 * reordered fields fails here instead of somewhere subtler.
 */
const PHC_PATTERN =
  /^\$([a-z0-9]+)\$v=(\d{1,3})\$m=(\d{1,9}),t=(\d{1,3}),p=(\d{1,3})\$([^$]+)\$([^$]+)$/;

/** The parameters and material recovered from a stored PHC string. */
interface ParsedHash {
  readonly memoryKib: number;
  readonly iterations: number;
  readonly parallelism: number;
  readonly salt: Uint8Array;
  /** The stored digest, re-encoded canonically for comparison. */
  readonly hash: string;
  readonly hashBytes: number;
}

/**
 * Recovers the parameters and salt from a stored PHC string.
 *
 * @param stored - The value read from the database.
 * @returns The parsed hash, or `undefined` when the value is not a well-formed
 *   `argon2id` v19 PHC string with parameters inside {@link STORED_LIMITS}.
 */
function parseStoredHash(stored: string): ParsedHash | undefined {
  const match = PHC_PATTERN.exec(stored);
  if (match === null) {
    return undefined;
  }

  const [, variant, version, memory, iterations, parallelism, salt, hash] =
    match;
  if (variant !== VARIANT || Number(version) !== VERSION) {
    return undefined;
  }

  const memoryKib = Number(memory);
  const iterationCount = Number(iterations);
  const parallelismCount = Number(parallelism);
  const saltBytes = decodeBase64(salt ?? "");
  const hashBytes = decodeBase64(hash ?? "");

  if (saltBytes === undefined || hashBytes === undefined) {
    return undefined;
  }

  const withinLimits =
    memoryKib >= STORED_LIMITS.minMemoryKib &&
    memoryKib <= STORED_LIMITS.maxMemoryKib &&
    iterationCount >= STORED_LIMITS.minIterations &&
    iterationCount <= STORED_LIMITS.maxIterations &&
    parallelismCount >= STORED_LIMITS.minParallelism &&
    parallelismCount <= STORED_LIMITS.maxParallelism &&
    saltBytes.length >= STORED_LIMITS.minSaltBytes &&
    saltBytes.length <= STORED_LIMITS.maxSaltBytes &&
    hashBytes.length >= STORED_LIMITS.minHashBytes &&
    hashBytes.length <= STORED_LIMITS.maxHashBytes &&
    // Argon2 itself requires at least eight kibibytes per lane.
    memoryKib >= 8 * parallelismCount;

  if (!withinLimits) {
    return undefined;
  }

  return {
    memoryKib,
    iterations: iterationCount,
    parallelism: parallelismCount,
    salt: saltBytes,
    hash: encodeBase64(hashBytes),
    hashBytes: hashBytes.length,
  };
}

/**
 * Formats an Argon2id result as a PHC string.
 *
 * The encoding is byte-identical to the reference implementation's, so a hash
 * written by Signet can be verified by any other Argon2 library and vice versa.
 */
function formatPhc(
  parameters: { memoryKib: number; iterations: number; parallelism: number },
  salt: Uint8Array,
  hash: Uint8Array,
): string {
  const { memoryKib, iterations, parallelism } = parameters;
  return [
    "",
    VARIANT,
    `v=${VERSION}`,
    `m=${memoryKib},t=${iterations},p=${parallelism}`,
    encodeBase64(salt),
    encodeBase64(hash),
  ].join("$");
}

/**
 * Hashes a password for storage.
 *
 * @param password - The cleartext password. Never logged, never stored, and not
 *   length-limited here - password policy belongs to the caller.
 * @returns A self-describing PHC string carrying the variant, version,
 *   parameters and a fresh 16-byte random salt, so that the parameters can be
 *   raised later without invalidating a single existing hash.
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const hash = await argon2id({
    password,
    salt,
    iterations: CURRENT_PARAMETERS.iterations,
    parallelism: CURRENT_PARAMETERS.parallelism,
    memorySize: CURRENT_PARAMETERS.memoryKib,
    hashLength: HASH_BYTES,
    outputType: "binary",
  });

  return formatPhc(CURRENT_PARAMETERS, salt, hash);
}

/**
 * Verifies a password against a stored hash.
 *
 * The parameters come out of `stored`, never from {@link CURRENT_PARAMETERS}, so
 * an account whose hash predates a parameter increase still authenticates.
 *
 * @param password - The cleartext password as presented.
 * @param stored - The PHC string from the database.
 * @returns True on a match. False on a mismatch *and* on a malformed, empty or
 *   foreign stored value: a wrong password is an expected outcome on a login
 *   path, and a corrupt row must fail closed rather than throw an exception that
 *   a caller might mistake for an infrastructure fault.
 */
export async function verifyPassword(
  password: string,
  stored: string,
): Promise<boolean> {
  const parsed = parseStoredHash(stored);
  if (parsed === undefined) {
    return false;
  }

  try {
    const computed = await argon2id({
      password,
      salt: parsed.salt,
      iterations: parsed.iterations,
      parallelism: parsed.parallelism,
      memorySize: parsed.memoryKib,
      hashLength: parsed.hashBytes,
      outputType: "binary",
    });

    return timingSafeEqual(encodeBase64(computed), parsed.hash);
  } catch {
    // The parameters are bounds-checked above, so reaching here means the
    // WebAssembly module refused the input - an unusable hash, not a match.
    return false;
  }
}

/**
 * True when a stored hash should be replaced after a successful login.
 *
 * A login already holds the cleartext password, so it is the one moment at which
 * a hash can be upgraded silently. Callers should re-run {@link hashPassword}
 * and write the result whenever this returns true.
 *
 * @param stored - The PHC string from the database.
 * @returns True when the hash is unparseable, uses a variant or version Signet
 *   no longer issues, or was minted with any cost parameter weaker than today's.
 *   A hash that is *stronger* than today's is left alone - this never downgrades
 *   an account.
 */
export function needsRehash(stored: string): boolean {
  const parsed = parseStoredHash(stored);
  if (parsed === undefined) {
    // Unparseable, so verification can never succeed against it. Reporting true
    // means a caller that does manage to authenticate the user by some other
    // means replaces the junk instead of preserving it.
    return true;
  }

  return (
    parsed.memoryKib < CURRENT_PARAMETERS.memoryKib ||
    parsed.iterations < CURRENT_PARAMETERS.iterations ||
    parsed.parallelism < CURRENT_PARAMETERS.parallelism ||
    parsed.salt.length < SALT_BYTES ||
    parsed.hashBytes < HASH_BYTES
  );
}
