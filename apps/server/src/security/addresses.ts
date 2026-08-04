/**
 * Classification of IP addresses, for the outbound-fetch guard.
 *
 * Signet fetches two things from URLs an operator or a developer supplied: a
 * client's `jwks_uri`, and an upstream identity provider's discovery document.
 * Both are server-side requests to an attacker-influenced address, which is the
 * definition of SSRF - and an authorization server is an unusually valuable
 * place to have one, because it runs inside the same network as the FHIR servers
 * it fronts and, in a cloud deployment, next to a metadata service that hands out
 * credentials to anything that asks.
 *
 * The guard is an allowlist by exclusion: an address is fetched only if it is
 * classified `public`. Every range with any special meaning is refused, including
 * ones that look harmless. `169.254.169.254` is the cloud metadata address and is
 * covered by link-local; `100.64.0.0/10` is carrier-grade NAT and reaches other
 * tenants on some providers; the documentation and benchmarking ranges are
 * refused because a URL pointing at one is a misconfiguration worth surfacing
 * rather than a request worth making.
 *
 * Everything here is pure and total: an unparseable input is reported as such
 * rather than throwing, because these values come from request bodies.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc5735
 * @see https://datatracker.ietf.org/doc/html/rfc6890
 *
 * Author: John Grimes
 */

/**
 * What an address is for.
 *
 * Only `public` is fetchable. The others are named individually rather than
 * collapsed into `blocked` so that a refusal can say which range it hit, which
 * is the difference between a usable error message and "request failed".
 */
export type AddressClassification =
  | "public"
  /** `0.0.0.0`, `::` - "this host", and on some stacks a route to localhost. */
  | "unspecified"
  /** `127.0.0.0/8`, `::1`. */
  | "loopback"
  /** RFC 1918: `10/8`, `172.16/12`, `192.168/16`. */
  | "private"
  /** IPv6 unique local addresses, `fc00::/7`. */
  | "unique-local"
  /** Carrier-grade NAT, `100.64.0.0/10`. */
  | "shared"
  /** `169.254/16`, `fe80::/10` - includes the cloud metadata address. */
  | "link-local"
  /** `224/4`, `ff00::/8`. */
  | "multicast"
  /** IETF protocol assignments, future use, and the IPv4 broadcast address. */
  | "reserved"
  /** `192.0.2/24`, `198.51.100/24`, `203.0.113/24`, `2001:db8::/32`. */
  | "documentation"
  /** `198.18/15`. */
  | "benchmarking";

/**
 * Parses a strict dotted-quad IPv4 address.
 *
 * Strict on purpose. `inet_aton` accepts `0177.0.0.1`, `2130706433` and
 * `127.1`, all of which are `127.0.0.1` to a C resolver and none of which look
 * like loopback to a naive string check - a classic SSRF filter bypass. Rejecting
 * everything but four plain decimal octets means the classification below sees the
 * same address the network stack will.
 */
export function parseIpv4(text: string): Uint8Array | undefined {
  const parts = text.split(".");
  if (parts.length !== 4) {
    return undefined;
  }

  const bytes = new Uint8Array(4);
  for (const [index, part] of parts.entries()) {
    // No leading zeros: `010` is octal to some parsers and decimal to others.
    if (!/^(?:0|[1-9]\d{0,2})$/.test(part)) {
      return undefined;
    }
    const value = Number(part);
    if (value > 255) {
      return undefined;
    }
    bytes[index] = value;
  }
  return bytes;
}

/** Writes a 16-bit group into a byte buffer at a group index. */
function writeGroup(bytes: Uint8Array, group: number, value: number): void {
  bytes[group * 2] = (value >> 8) & 0xff;
  bytes[group * 2 + 1] = value & 0xff;
}

/**
 * Parses an IPv6 address, including the `::` elision and an embedded IPv4 tail.
 *
 * Surrounding brackets are accepted because that is how the address appears in a
 * URL's host component, and a caller working from `URL.hostname` would otherwise
 * have to strip them itself and get it wrong once.
 */
export function parseIpv6(text: string): Uint8Array | undefined {
  const bracketed = text.startsWith("[") && text.endsWith("]");
  let raw = bracketed ? text.slice(1, -1) : text;
  // A zone identifier (`fe80::1%eth0`) is not valid in a URL host and is not
  // accepted; it would also make the address non-comparable.
  if (raw.length === 0 || raw.includes("%")) {
    return undefined;
  }

  // An embedded IPv4 tail is rewritten as the two hex groups it denotes, so that
  // the group parsing below has exactly one syntax to handle. `::ffff:127.0.0.1`
  // becomes `::ffff:7f00:1`, which is the same address.
  if (raw.includes(".")) {
    const lastColon = raw.lastIndexOf(":");
    if (lastColon === -1) {
      return undefined;
    }
    const embedded = parseIpv4(raw.slice(lastColon + 1));
    if (embedded === undefined) {
      return undefined;
    }
    const high = ((embedded[0] ?? 0) << 8) | (embedded[1] ?? 0);
    const low = ((embedded[2] ?? 0) << 8) | (embedded[3] ?? 0);
    raw = `${raw.slice(0, lastColon + 1)}${high.toString(16)}:${low.toString(16)}`;
  }

  const elision = raw.indexOf("::");
  if (elision !== raw.lastIndexOf("::")) {
    return undefined;
  }

  const headText = elision === -1 ? raw : raw.slice(0, elision);
  const tailText = elision === -1 ? "" : raw.slice(elision + 2);

  const head = parseHexGroups(headText);
  const tail = parseHexGroups(tailText);
  if (head === undefined || tail === undefined) {
    return undefined;
  }

  const total = head.length + tail.length;
  // Without an elision every group must be written; with one, at least one group
  // must actually be elided, so seven is the most that may be written.
  if (elision === -1 ? total !== 8 : total > 7) {
    return undefined;
  }

  const bytes = new Uint8Array(16);
  for (const [index, value] of head.entries()) {
    writeGroup(bytes, index, value);
  }
  for (const [index, value] of tail.entries()) {
    writeGroup(bytes, 8 - tail.length + index, value);
  }
  return bytes;
}

/** Parses a colon-delimited run of hex groups. An empty string yields none. */
function parseHexGroups(text: string): number[] | undefined {
  if (text.length === 0) {
    return [];
  }
  const groups: number[] = [];
  for (const part of text.split(":")) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(part)) {
      return undefined;
    }
    groups.push(Number.parseInt(part, 16));
  }
  return groups;
}

/** Classifies four bytes of IPv4 address. */
function classifyIpv4Bytes(bytes: Uint8Array): AddressClassification {
  const [a = 0, b = 0, c = 0, d = 0] = bytes;

  if (a === 0 && b === 0 && c === 0 && d === 0) {
    return "unspecified";
  }
  if (a === 0) {
    return "reserved";
  }
  if (a === 10) {
    return "private";
  }
  if (a === 127) {
    return "loopback";
  }
  if (a === 100 && b >= 64 && b <= 127) {
    return "shared";
  }
  if (a === 169 && b === 254) {
    return "link-local";
  }
  if (a === 172 && b >= 16 && b <= 31) {
    return "private";
  }
  if (a === 192 && b === 168) {
    return "private";
  }
  if (a === 192 && b === 0 && c === 0) {
    return "reserved";
  }
  if (a === 192 && b === 0 && c === 2) {
    return "documentation";
  }
  if (a === 198 && (b === 18 || b === 19)) {
    return "benchmarking";
  }
  if (a === 198 && b === 51 && c === 100) {
    return "documentation";
  }
  if (a === 203 && b === 0 && c === 113) {
    return "documentation";
  }
  if (a === 255 && b === 255 && c === 255 && d === 255) {
    return "reserved";
  }
  if (a >= 224 && a <= 239) {
    return "multicast";
  }
  if (a >= 240) {
    return "reserved";
  }
  return "public";
}

/**
 * The IPv4 address an IPv6 address embeds, when it embeds one.
 *
 * `::ffff:a.b.c.d` is the IPv4-mapped form and `::a.b.c.d` the deprecated
 * IPv4-compatible form. Both reach an IPv4 destination, so both are classified as
 * the address they carry - otherwise `::ffff:127.0.0.1` would read as a public
 * IPv6 address and be fetched, which is the oldest bypass of this kind of filter.
 *
 * Called only after `::` and `::1` have been handled, so the all-zero and
 * loopback forms cannot reach it and be misread as `0.0.0.0` or `0.0.0.1`.
 */
function embeddedIpv4(bytes: Uint8Array): Uint8Array | undefined {
  if (!bytes.slice(0, 10).every((byte) => byte === 0)) {
    return undefined;
  }
  const marker = ((bytes[10] ?? 0) << 8) | (bytes[11] ?? 0);
  return marker === 0xff_ff || marker === 0 ? bytes.slice(12, 16) : undefined;
}

/** Classifies sixteen bytes of IPv6 address. */
function classifyIpv6Bytes(bytes: Uint8Array): AddressClassification {
  if (bytes.every((byte) => byte === 0)) {
    return "unspecified";
  }
  if (bytes.slice(0, 15).every((byte) => byte === 0) && bytes[15] === 1) {
    return "loopback";
  }

  const embedded = embeddedIpv4(bytes);
  if (embedded !== undefined) {
    return classifyIpv4Bytes(embedded);
  }

  const first = bytes[0] ?? 0;
  const second = bytes[1] ?? 0;

  if (first === 0xff) {
    return "multicast";
  }
  if ((first & 0xfe) === 0xfc) {
    return "unique-local";
  }
  if (first === 0xfe && (second & 0xc0) === 0x80) {
    return "link-local";
  }
  if (
    first === 0x20 &&
    second === 0x01 &&
    bytes[2] === 0x0d &&
    bytes[3] === 0xb8
  ) {
    return "documentation";
  }
  // `2002::/16` (6to4) and `2001::/32` (Teredo) both tunnel to an arbitrary IPv4
  // destination, so an address in either can reach a private network without
  // looking like it.
  if (first === 0x20 && second === 0x02) {
    return "reserved";
  }
  if (first === 0x20 && second === 0x01 && bytes[2] === 0 && bytes[3] === 0) {
    return "reserved";
  }
  return "public";
}

/**
 * Classifies an IP address literal.
 *
 * @param text - A dotted-quad or IPv6 literal, with or without brackets.
 * @returns The classification, or undefined when the value is not an IP address
 *   at all - which for a URL host means it is a DNS name and must be resolved
 *   before it can be judged.
 */
export function classifyIpAddress(
  text: string,
): AddressClassification | undefined {
  const ipv4 = parseIpv4(text);
  if (ipv4 !== undefined) {
    return classifyIpv4Bytes(ipv4);
  }
  const ipv6 = parseIpv6(text);
  return ipv6 === undefined ? undefined : classifyIpv6Bytes(ipv6);
}

/**
 * Whether an address may be fetched.
 *
 * An unparseable value is not fetchable: this function is a gate, and "I could
 * not tell what this is" must never mean yes.
 */
export function isFetchableAddress(text: string): boolean {
  return classifyIpAddress(text) === "public";
}
