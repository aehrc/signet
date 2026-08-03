/**
 * Credential stripping for audit detail blobs.
 *
 * The audit log is append-only, which makes this the highest-consequence
 * function in the package: a plaintext client secret written here cannot be
 * un-written, and the row it sits in is one the product promises never to
 * modify or delete. Detail blobs are assembled at dozens of call sites, often by
 * spreading a request body or an error object, so the safe assumption is that
 * every blob contains a credential until proven otherwise.
 *
 * The strategy is therefore deny-list by key, applied to the whole subtree under
 * a matching key, plus a value-shape check that catches credentials smuggled
 * under an innocuous name. Matching values are replaced with a marker rather than
 * dropped, so the trail still records that (say) a client secret was supplied —
 * an absent key and a rejected credential are very different events.
 *
 * Known limitation: a credential that appears as a bare array element or as part
 * of a longer string under a harmless key (`{ argv: ["--secret", "hunter2"] }`)
 * is only caught if it happens to match one of the value patterns. Call sites
 * must not build detail blobs that way.
 */

/** Replaces a value that matched the deny-list. */
export const REDACTED_MARKER = "[redacted]";

/** Replaces a value elided by a depth, breadth or size cap. */
export const TRUNCATED_MARKER = "[truncated]";

/** Replaces a value that refers back to one of its own ancestors. */
export const CYCLE_MARKER = "[cycle]";

/** Replaces a value with no JSON representation, such as a function. */
export const UNSUPPORTED_MARKER = "[unsupported]";

/**
 * Nesting levels retained. A blob deeper than this is either a serialised
 * framework object that nobody will read or an attempt to bury a secret below
 * the redactor's reach; both are better truncated.
 */
const MAX_DEPTH = 6;

/**
 * Total values visited. Bounds both the work done on a hostile input and the row
 * size, since an unbounded blob in an append-only table is a disk-exhaustion
 * vector.
 */
const MAX_NODES = 512;

/** Characters kept from a single string value. */
const MAX_STRING_LENGTH = 2048;

/** Array elements kept. */
const MAX_ARRAY_ITEMS = 64;

/** Object keys kept per level. */
const MAX_OBJECT_KEYS = 64;

/**
 * Key fragments whose value is always a credential, or close enough to one that
 * redacting it costs nothing.
 *
 * Matched as substrings of the *normalised* key (lower-cased with every
 * non-alphanumeric character removed), so `client_secret`, `clientSecret`,
 * `Client-Secret` and `CLIENTSECRET` are one entry.
 *
 * `token` is deliberately broad: it also catches `token_type` and `tokenId`,
 * which are harmless, and over-redaction is the correct direction to err in. A
 * call site that needs a token's identity in the trail should record `jti`.
 */
export const REDACTED_KEY_SUBSTRINGS: readonly string[] = [
  "password",
  "passwd",
  "passphrase",
  "secret",
  "credential",
  "token",
  "bearer",
  // Both spellings: the HTTP header is `authorization`, the product's prose is
  // British, and a call site may well have used either.
  "authorization",
  "authorisation",
  "cookie",
  // `client_assertion` for private_key_jwt client authentication.
  "assertion",
  "codeverifier",
  "privatekey",
  "privatejwk",
  "apikey",
  "masterkey",
  "signingkey",
  "encryptionkey",
  // An admin session identifier is a bearer credential in its own right.
  "sessionid",
  "recoverycode",
];

/**
 * Short key names that are credentials on their own but too generic to match as
 * substrings — `code` must not redact `status_code` or `code_challenge_method`.
 *
 * Matched against the whole normalised key.
 */
export const REDACTED_KEY_EXACT: readonly string[] = [
  "code",
  "verifier",
  "otp",
  "totp",
  "pin",
  // A bare `jwk` may be a private key; `jwks` and `jwks_uri` are public and
  // survive, which is why this is an exact match rather than a substring.
  "jwk",
  "key",
];

/**
 * Value shapes that are credentials whatever they are called.
 *
 * These catch the common mistake of logging a whole header value or a signed
 * token under a descriptive name such as `supplied` or `raw`.
 */
const CREDENTIAL_VALUE_PATTERNS: readonly RegExp[] = [
  // A compact JWS or JWT: three base64url segments, the first decoding to `{"`.
  /^ey[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\./,
  // An HTTP authorization header value.
  /^(?:bearer|basic|dpop)\s+\S/i,
  // A PEM-encoded private key.
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/,
];

interface Budget {
  nodes: number;
}

/**
 * Reduces a key to its comparable form: lower case, alphanumeric only.
 *
 * This is what collapses `client_secret`, `clientSecret` and `Client Secret`
 * onto one deny-list entry.
 *
 * @param key - Raw object key.
 */
function normaliseKey(key: string): string {
  return key.toLowerCase().replaceAll(/[^a-z0-9]/g, "");
}

/**
 * Reports whether values under this key must be redacted.
 *
 * @param key - Raw object key.
 */
export function isSensitiveKey(key: string): boolean {
  const normalised = normaliseKey(key);
  if (REDACTED_KEY_EXACT.includes(normalised)) {
    return true;
  }
  return REDACTED_KEY_SUBSTRINGS.some((fragment) =>
    normalised.includes(fragment),
  );
}

/**
 * Redacts or truncates a single string value.
 *
 * @param value - String to inspect.
 */
function redactString(value: string): string {
  if (CREDENTIAL_VALUE_PATTERNS.some((pattern) => pattern.test(value))) {
    return REDACTED_MARKER;
  }
  if (value.length > MAX_STRING_LENGTH) {
    return `${value.slice(0, MAX_STRING_LENGTH)}${TRUNCATED_MARKER}`;
  }
  return value;
}

/**
 * Applies the value-shape check and the length cap to a single string.
 *
 * Exported for the handful of typed string fields that are merged into a detail
 * blob after it has been redacted — reserved keys such as the actor's display
 * name, which must overwrite anything the call site put there and so cannot go
 * through the blob itself.
 *
 * @param value - String to clamp and check.
 */
export function redactAuditText(value: string): string {
  return redactString(value);
}

/**
 * Recursively normalises one value into something JSONB can hold, redacting as
 * it goes.
 *
 * `ancestors` holds only the objects on the current path, not every object seen,
 * so a value referenced twice as a sibling is kept while a genuine cycle is
 * marked. Without that distinction a legitimately shared sub-object would
 * vanish from the trail.
 *
 * @param value - Value to normalise.
 * @param depth - Nesting level of this value; 0 is the blob itself.
 * @param budget - Shared remaining-node counter.
 * @param ancestors - Objects on the path from the root to here.
 */
function redactValue(
  value: unknown,
  depth: number,
  budget: Budget,
  ancestors: Set<object>,
): unknown {
  if (budget.nodes >= MAX_NODES) {
    return TRUNCATED_MARKER;
  }
  budget.nodes += 1;

  if (value === null || value === undefined) {
    // `undefined` becomes `null` rather than disappearing: JSON.stringify would
    // drop the key, and a key that was present with no value is information.
    return null;
  }

  switch (typeof value) {
    case "string": {
      return redactString(value);
    }
    case "number": {
      // NaN and the infinities have no JSON form and would serialise to `null`
      // anyway; doing it here keeps the output identical across drivers.
      return Number.isFinite(value) ? value : null;
    }
    case "boolean": {
      return value;
    }
    case "bigint": {
      return value.toString();
    }
    case "function":
    case "symbol": {
      return UNSUPPORTED_MARKER;
    }
    default: {
      break;
    }
  }

  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value.toISOString();
  }

  const container = value;
  if (ancestors.has(container)) {
    return CYCLE_MARKER;
  }
  if (depth >= MAX_DEPTH) {
    return TRUNCATED_MARKER;
  }

  ancestors.add(container);
  try {
    if (Array.isArray(value)) {
      return redactArray(value, depth, budget, ancestors);
    }
    if (value instanceof Set) {
      return redactArray([...value], depth, budget, ancestors);
    }
    if (value instanceof Map) {
      // Converted rather than left alone: a Map serialises to `{}`, which would
      // silently discard whatever it held — including, possibly, the reason the
      // event was recorded.
      return redactEntries(
        [...value.entries()].map(
          ([key, entry]) => [String(key), entry] as const,
        ),
        depth,
        budget,
        ancestors,
      );
    }
    if (value instanceof Error) {
      // Deliberately not the stack: it is long, it is not information about the
      // decision taken, and it frequently quotes arguments.
      return {
        name: value.name,
        message: redactString(value.message),
      };
    }
    return redactEntries(
      Object.entries(value as Record<string, unknown>),
      depth,
      budget,
      ancestors,
    );
  } finally {
    ancestors.delete(container);
  }
}

/**
 * Normalises an array, capping its length.
 *
 * @param values - Elements to normalise.
 * @param depth - Nesting level of the array itself.
 * @param budget - Shared remaining-node counter.
 * @param ancestors - Objects on the path from the root to here.
 */
function redactArray(
  values: readonly unknown[],
  depth: number,
  budget: Budget,
  ancestors: Set<object>,
): unknown[] {
  const kept = values
    .slice(0, MAX_ARRAY_ITEMS)
    .map((entry) => redactValue(entry, depth + 1, budget, ancestors));
  if (values.length > MAX_ARRAY_ITEMS) {
    kept.push(TRUNCATED_MARKER);
  }
  return kept;
}

/**
 * Normalises a set of key/value pairs, redacting sensitive keys outright.
 *
 * A sensitive key's whole subtree is replaced, not descended into: an object
 * named `credentials` is assumed to contain nothing that is safe to keep.
 *
 * @param entries - Key/value pairs to normalise.
 * @param depth - Nesting level of the object itself.
 * @param budget - Shared remaining-node counter.
 * @param ancestors - Objects on the path from the root to here.
 */
function redactEntries(
  entries: readonly (readonly [string, unknown])[],
  depth: number,
  budget: Budget,
  ancestors: Set<object>,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of entries.slice(0, MAX_OBJECT_KEYS)) {
    if (isSensitiveKey(key)) {
      budget.nodes += 1;
      result[key] = REDACTED_MARKER;
      continue;
    }
    result[key] = redactValue(value, depth + 1, budget, ancestors);
  }
  if (entries.length > MAX_OBJECT_KEYS) {
    result[TRUNCATED_MARKER] = entries.length - MAX_OBJECT_KEYS;
  }
  return result;
}

/**
 * Strips credentials from an audit detail blob and normalises it for JSONB.
 *
 * Always returns an object, because `audit_events.detail` is `NOT NULL` and a
 * JSONB scalar would make the console's rendering conditional on the shape of
 * something many call sites write. A blob that is not an object is wrapped as
 * `{ value }`; `null` and `undefined` become `{}`.
 *
 * @param detail - Whatever the call site wants recorded.
 * @returns A credential-free, cycle-free, size-bounded object.
 */
export function redactAuditDetail(detail: unknown): Record<string, unknown> {
  const normalised = redactValue(detail, 0, { nodes: 0 }, new Set());
  if (normalised === null) {
    return {};
  }
  if (
    typeof normalised === "object" &&
    !Array.isArray(normalised) &&
    normalised !== null
  ) {
    return normalised as Record<string, unknown>;
  }
  return { value: normalised };
}
