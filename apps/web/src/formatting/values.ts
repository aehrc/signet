/**
 * Turning API values into text a person can read.
 *
 * All pure, all tested. These are the functions that would otherwise be inlined
 * into JSX and quietly get the plural wrong, or format a null as "null" - and
 * they are the reason the components below contain almost no logic.
 *
 * Nothing here uses the current time as an ambient value: `now` is a parameter
 * everywhere it is needed, so a relative timestamp is a pure function of two
 * instants rather than of one instant and a clock.
 *
 * Author: John Grimes
 */

/** Fixed English locale, so a screenshot means the same thing everywhere. */
const LOCALE = "en-AU";

/** How each duration unit divides down from seconds. */
const DURATION_UNITS: readonly {
  readonly seconds: number;
  readonly name: string;
}[] = [
  { seconds: 86_400, name: "day" },
  { seconds: 3600, name: "hour" },
  { seconds: 60, name: "minute" },
  { seconds: 1, name: "second" },
];

/**
 * Formats an instant as an absolute date and time.
 *
 * @param value - An ISO timestamp, or null for a value the API did not set.
 * @returns The formatted date, or an em-dash-free placeholder for null.
 */
export function formatInstant(value: string | null | undefined): string {
  if (value === null || value === undefined) {
    return "never";
  }
  const at = new Date(value);
  if (Number.isNaN(at.getTime())) {
    return value;
  }
  return at.toLocaleString(LOCALE, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/**
 * Formats an instant as a rough interval from `now`.
 *
 * Deliberately coarse: an audit list is read for ordering and recency, and "3
 * minutes ago" is more useful at a glance than a timestamp. The exact value is
 * always available as a title attribute beside it.
 *
 * @param value - An ISO timestamp.
 * @param now - The instant to measure from.
 */
export function formatSince(
  value: string | null | undefined,
  now: Date,
): string {
  if (value === null || value === undefined) {
    return "never";
  }
  const at = new Date(value);
  if (Number.isNaN(at.getTime())) {
    return value;
  }

  const seconds = Math.round((now.getTime() - at.getTime()) / 1000);
  if (seconds < 0) {
    return "in the future";
  }
  if (seconds < 45) {
    return "just now";
  }

  for (const unit of DURATION_UNITS) {
    const count = Math.floor(seconds / unit.seconds);
    if (count >= 1) {
      return `${String(count)} ${pluralise(unit.name, count)} ago`;
    }
  }
  return "just now";
}

/**
 * Formats a duration in seconds as the largest whole unit that fits.
 *
 * Used for token lifetimes, which an operator thinks about as "five minutes" and
 * the API carries as 300.
 *
 * @param seconds - The duration.
 */
export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return "0 seconds";
  }
  for (const unit of DURATION_UNITS) {
    if (seconds >= unit.seconds) {
      const count = Math.round((seconds / unit.seconds) * 10) / 10;
      return `${String(count)} ${pluralise(unit.name, count)}`;
    }
  }
  return `${String(seconds)} seconds`;
}

/**
 * Pluralises an English noun by appending `s`.
 *
 * Sufficient because the vocabulary here is closed and regular: day, hour,
 * minute, second, scope, client, key. A general pluraliser would be a library and
 * a false promise.
 *
 * @param noun - The singular form.
 * @param count - How many there are.
 */
export function pluralise(noun: string, count: number): string {
  return count === 1 ? noun : `${noun}s`;
}

/**
 * "3 clients", with the noun agreeing.
 *
 * @param count - How many there are.
 * @param noun - The singular form.
 */
export function countOf(count: number, noun: string): string {
  return `${String(count)} ${pluralise(noun, count)}`;
}

/**
 * Words that are acronyms rather than words, keyed by the camel-case fragment.
 *
 * Without this, `supportsEhrLaunch` reads as "Ehr launch".
 */
const ACRONYMS: Readonly<Record<string, string>> = {
  Ehr: "EHR",
  Id: "ID",
  Oidc: "OIDC",
  Url: "URL",
  Uri: "URI",
  Jwks: "JWKS",
  Ttl: "TTL",
  V1: "v1",
  V2: "v2",
};

/**
 * Names whose derived label would read badly enough to be worth stating.
 *
 * Deliberately short. Everything not here is derived, so a capability added to the
 * API appears in the console without an edit - the alternative is twenty-two labels
 * to keep in step with the server.
 */
const CAPABILITY_LABELS: Readonly<Record<string, string>> = {
  supportsOpenIdConnect: "OpenID Connect single sign-on",
  supportsAuthorizePost: "POST to /authorize",
};

/**
 * Turns a camel-case capability name into a label.
 *
 * `supportsEhrLaunch` becomes "EHR launch": the prefix says nothing a person needs
 * to read, and an acronym in the middle should stay one.
 *
 * @param name - The API's flag name.
 */
export function capabilityLabel(name: string): string {
  const stated = CAPABILITY_LABELS[name];
  if (stated !== undefined) {
    return stated;
  }

  const words = name
    .replace(/^(supports|allows)/, "")
    .split(/(?=[A-Z])/)
    .filter((word) => word !== "");
  if (words.length === 0) {
    return name;
  }

  return words
    .map((word, index) => {
      const acronym = ACRONYMS[word];
      if (acronym !== undefined) {
        return acronym;
      }
      // Only the first word is capitalised: this is a label in a list, not a
      // title, and "Standalone Launch" reads as two proper nouns.
      return index === 0 ? word : word.toLowerCase();
    })
    .join(" ");
}

/**
 * A short, stable label for a client's authentication posture.
 *
 * @param clientType - The API's client type.
 */
export function clientTypeLabel(clientType: string): string {
  switch (clientType) {
    case "public": {
      return "Public";
    }
    case "confidential-symmetric": {
      return "Confidential (secret)";
    }
    case "confidential-asymmetric": {
      return "Confidential (key)";
    }
    default: {
      return clientType;
    }
  }
}

/**
 * Truncates a long value for a table cell, keeping the start.
 *
 * The start, because these are identifiers, URLs and scope strings, where the
 * distinguishing part is at the front.
 *
 * @param value - The text to shorten.
 * @param maximum - Longest result, including the ellipsis.
 */
export function truncate(value: string, maximum = 48): string {
  if (value.length <= maximum) {
    return value;
  }
  return `${value.slice(0, Math.max(0, maximum - 1))}…`;
}
