/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The only way Signet makes an outbound HTTP request.
 *
 * Two URLs in the data model are supplied by somebody other than the operator of
 * the Signet deployment: a client's `jwks_uri` and an upstream identity
 * provider's issuer. Fetching either is a server-side request to an
 * attacker-influenced address, and an authorization server is a particularly bad
 * place to have one - it sits inside the network holding the FHIR servers it
 * fronts, and in a cloud deployment beside a metadata service that will hand out
 * credentials to any process that asks.
 *
 * The guard has four parts, and all four matter:
 *
 * 1. **Scheme.** `https` only, unless a deployment explicitly opts into plain
 *    HTTP for a development or connectathon stack. `file:`, `gopher:` and the
 *    rest are refused by the same check.
 * 2. **No userinfo.** `https://metadata@attacker.example/` and its inverse are
 *    the standard way to make a URL's apparent host differ from its real one.
 * 3. **Address.** The hostname is resolved, and *every* address it resolves to
 *    must be publicly routable. Checking the name is useless - `localtest.me`
 *    resolves to `127.0.0.1` - and checking only the first address lets a
 *    multi-A-record name slip a private address past.
 * 4. **No redirects.** A redirect is a second URL that the guard never saw. Rather
 *    than re-running the check per hop, redirects are refused outright: a JWKS
 *    endpoint has no legitimate need to redirect, and neither does a discovery
 *    document.
 *
 * **The residual risk.** Between resolving the name and connecting, the DNS
 * answer could change - DNS rebinding. The window is closed rather than accepted:
 * the transport the request goes over resolves through {@link pinnedLookup},
 * which hands the socket exactly the addresses the guard validated, so the
 * connection is made to an address that was checked and never to a fresh answer
 * from a rebinding server. The redirect refusal and the address classifier above
 * are what make the pinned set safe to trust.
 *
 * Author: John Grimes
 */

import { lookup } from "node:dns/promises";
import { Agent, fetch as undiciFetch } from "undici";

import { isFetchableAddress } from "./addresses.js";

import type { LookupAddress } from "node:dns";
import type { LookupFunction } from "node:net";

/** Why an outbound request was refused. */
export type OutboundRefusal =
  | "not-a-url"
  | "insecure-scheme"
  | "userinfo"
  | "blocked-address"
  | "unresolvable"
  | "redirected"
  | "unreachable"
  | "bad-status"
  | "too-large"
  | "not-json";

/** The outcome of checking a URL before it is fetched. */
export type OutboundUrlCheck =
  | { readonly ok: true; readonly url: URL }
  | {
      readonly ok: false;
      readonly reason: OutboundRefusal;
      readonly description: string;
    };

/** The outcome of a guarded fetch. */
export type OutboundResult<T> =
  | { readonly ok: true; readonly value: T }
  | {
      readonly ok: false;
      readonly reason: OutboundRefusal;
      readonly description: string;
    };

/** Resolves a hostname to every address it names. Injected so tests need no DNS. */
export type AddressResolver = (hostname: string) => Promise<readonly string[]>;

export interface OutboundFetchOptions {
  /**
   * Permits plain HTTP and private addresses.
   *
   * For development and connectathon stacks, where the upstream IdP is
   * `http://keycloak:8080` on a compose network. Never for production: it turns
   * every check above off at once, which is why it is a single obvious flag and
   * not a set of independent ones.
   */
  readonly allowPrivateAddresses?: boolean;
  /** Abandons the request after this many milliseconds. */
  readonly timeoutMs?: number;
  /** Refuses a response body larger than this many bytes. */
  readonly maxBytes?: number;
  readonly resolve?: AddressResolver;
  /**
   * Overrides how the transport is bound to the addresses the guard validated.
   *
   * For the tests: the default factory builds a transport whose connections can
   * only be made to the validated addresses, which cannot be observed without a
   * public host to bind. A test injects this to capture the set it is given.
   */
  readonly pinnedTransport?: (
    addresses: readonly string[],
  ) => OutboundTransport;
  /**
   * The transport, for the tests.
   *
   * The one call this module makes, rather than `typeof fetch`: the global carries
   * runtime-specific extras - `preconnect` under Bun's types, absent under Node's -
   * and a stub would have to grow them for no reason but to satisfy a signature.
   * Takes precedence over pinning, which is why no production caller passes it.
   */
  readonly fetchImpl?: OutboundTransport;
  /**
   * Sends a form-encoded POST instead of a GET.
   *
   * For the one outbound request that is not a document fetch: redeeming a code
   * at an upstream provider's token endpoint. It goes through this module rather
   * than calling `fetch` directly because the guard is about the destination, and
   * the token endpoint's URL came from the same untrusted discovery document as
   * everything else.
   */
  readonly form?: Readonly<Record<string, string>>;
  /**
   * Extra request headers.
   *
   * Used for `Authorization: Basic` on an upstream token request, and nothing
   * else. Never logged: the value is a client secret.
   */
  readonly headers?: Readonly<Record<string, string>>;
}

/** A transport a guarded request is made over. */
export type OutboundTransport = (
  input: URL,
  init: RequestInit,
) => Promise<Response>;

/** Ten seconds: long enough for a slow JWKS host, short enough not to pile up. */
export const DEFAULT_OUTBOUND_TIMEOUT_MS = 10_000;

/**
 * 256 KiB.
 *
 * A JWKS with a hundred keys is a few tens of kilobytes. The limit exists so that
 * a hostile host cannot exhaust memory by streaming indefinitely - the classic
 * decompression-bomb-adjacent denial of service against a fetching server.
 */
export const DEFAULT_OUTBOUND_MAX_BYTES = 262_144;

/**
 * How much of a failed response's body is quoted in the refusal.
 *
 * Enough for an OAuth error object, which is what this is for, and short enough
 * that a provider answering with an HTML error page contributes a line to the
 * audit trail rather than a screenful.
 */
const BAD_STATUS_BODY_CHARACTERS = 500;

/** Builds a refusal. */
function refuse(
  reason: OutboundRefusal,
  description: string,
): {
  readonly ok: false;
  readonly reason: OutboundRefusal;
  readonly description: string;
} {
  return { ok: false, reason, description };
}

/**
 * Checks a URL's syntax and, when the host is an IP literal, its address.
 *
 * Pure. A hostname that is not an IP literal passes this check and is judged
 * again after resolution by {@link fetchGuardedJson}.
 *
 * @param raw - The user-supplied URL.
 * @param allowPrivateAddresses - See {@link OutboundFetchOptions}.
 */
export function checkOutboundUrl(
  raw: string,
  allowPrivateAddresses = false,
): OutboundUrlCheck {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return refuse("not-a-url", `"${raw}" is not an absolute URL`);
  }

  const schemeAllowed =
    url.protocol === "https:" ||
    (allowPrivateAddresses && url.protocol === "http:");
  if (!schemeAllowed) {
    return refuse(
      "insecure-scheme",
      `Only https URLs may be fetched, not ${url.protocol}`,
    );
  }

  if (url.username.length > 0 || url.password.length > 0) {
    return refuse("userinfo", "A fetched URL may not carry userinfo");
  }

  if (url.hostname.length === 0) {
    return refuse("not-a-url", "The URL has no host");
  }

  // An IP literal can be judged now. A DNS name cannot, and is checked after
  // resolution - `isFetchableAddress` returns false for anything unparseable, so
  // it cannot be used here to reject names.
  const isLiteral =
    /^[\d.]+$/.test(url.hostname) || url.hostname.startsWith("[");
  if (
    isLiteral &&
    !allowPrivateAddresses &&
    !isFetchableAddress(url.hostname)
  ) {
    return refuse(
      "blocked-address",
      `${url.hostname} is not a publicly routable address`,
    );
  }

  return { ok: true, url };
}

/** Resolves a hostname to every address, via the system resolver. */
async function systemResolve(hostname: string): Promise<readonly string[]> {
  const results = await lookup(hostname, { all: true, verbatim: true });
  return results.map((result) => result.address);
}

/**
 * The lookup a pinned connection resolves through: it hands the socket exactly
 * the addresses the guard validated, and nothing else.
 *
 * `fetch` resolves a hostname again when it opens its connection, which is the
 * gap a rebinding DNS server walks through - validated once, connected elsewhere.
 * Giving the connection this lookup closes it: the question "what does the name
 * point at now" is never asked, because the socket is told where to go.
 *
 * @param addresses - The addresses {@link fetchGuardedJson} validated.
 * @returns A `node:dns` lookup function, as the transport's connector expects.
 */
export function pinnedLookup(addresses: readonly string[]): LookupFunction {
  return (_hostname: string, _options, callback): void => {
    if (addresses.length === 0) {
      callback(new Error("no validated addresses"), "");
      return;
    }
    callback(
      null,
      addresses.map((address): LookupAddress => ({
        address,
        family: address.includes(":") ? 6 : 4,
      })),
    );
  };
}

/**
 * The default pinned transport: an HTTP client whose connections resolve through
 * {@link pinnedLookup} over the validated addresses.
 *
 * The dispatcher is built per request rather than shared, because the validated
 * addresses belong to this request's hostname. Idle pooled connections are
 * reclaimed by the client's keep-alive timeout.
 *
 * @param addresses - The addresses the guard validated.
 */
export function pinnedTransport(
  addresses: readonly string[],
): OutboundTransport {
  const agent = new Agent({ connect: { lookup: pinnedLookup(addresses) } });
  return async (input, init) => {
    // undici's `Response` and the DOM one are structurally the same object in
    // every way this module reads - `ok`, `status`, and a streaming `body`.
    const requestInit = { ...init, dispatcher: agent } as Parameters<
      typeof undiciFetch
    >[1];
    const response = (await undiciFetch(
      input,
      requestInit,
    )) as unknown as Response;
    return response;
  };
}

/**
 * Reads a response body, refusing one that exceeds the byte limit.
 *
 * Streamed rather than buffered through `response.text()`, so an oversized body
 * is abandoned partway rather than fully read and then rejected. `Content-Length`
 * is not trusted: it is advisory, and a hostile host simply omits it.
 */
async function readBounded(
  response: Response,
  maxBytes: number,
): Promise<string | undefined> {
  const body = response.body;
  if (body === null) {
    return "";
  }

  // Annotated because the DOM lib types `getReader()` loosely enough that `value`
  // arrives as `any`, and an auth server should not have an unchecked `any` on the
  // path that reads a remote response.
  const reader: ReadableStreamDefaultReader<Uint8Array> = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      total += value.length;
      if (total > maxBytes) {
        return undefined;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  return new TextDecoder().decode(Buffer.concat(chunks));
}

/**
 * Fetches and parses a JSON document, through every check in the module header.
 *
 * @param raw - The user-supplied URL.
 * @param options - Overrides for the limits, and the injection points tests use.
 * @returns The parsed document, or why it was refused. Never throws for a network
 *   or content failure: every one of them is a value the caller has to audit.
 */
export async function fetchGuardedJson<T = unknown>(
  raw: string,
  options: OutboundFetchOptions = {},
): Promise<OutboundResult<T>> {
  const allowPrivate = options.allowPrivateAddresses ?? false;
  const check = checkOutboundUrl(raw, allowPrivate);
  if (!check.ok) {
    return check;
  }

  const resolver = options.resolve ?? systemResolve;
  const maxBytes = options.maxBytes ?? DEFAULT_OUTBOUND_MAX_BYTES;

  // The addresses the request may be connected to. Undefined means no
  // validated set exists - the guard is off, and the plain transport is right.
  let validated: readonly string[] | undefined;

  if (!allowPrivate) {
    let addresses: readonly string[];
    try {
      addresses = await resolver(check.url.hostname);
    } catch {
      return refuse(
        "unresolvable",
        `${check.url.hostname} could not be resolved`,
      );
    }
    if (addresses.length === 0) {
      return refuse(
        "unresolvable",
        `${check.url.hostname} resolved to no addresses`,
      );
    }
    // Every address, not the first: a name with both a public and a private A
    // record must be refused, or the choice of which to connect to decides
    // whether the guard held.
    const blocked = addresses.find((address) => !isFetchableAddress(address));
    if (blocked !== undefined) {
      return refuse(
        "blocked-address",
        `${check.url.hostname} resolves to ${blocked}, which is not publicly routable`,
      );
    }
    validated = addresses;
  }

  const doFetch =
    validated === undefined
      ? (options.fetchImpl ?? fetch)
      : (options.pinnedTransport?.(validated) ??
        options.fetchImpl ??
        pinnedTransport(validated));
  let response: Response;
  try {
    response = await doFetch(check.url, {
      method: options.form === undefined ? "GET" : "POST",
      headers: {
        accept: "application/json",
        ...(options.form === undefined
          ? {}
          : { "content-type": "application/x-www-form-urlencoded" }),
        ...options.headers,
      },
      ...(options.form === undefined
        ? {}
        : { body: new URLSearchParams(options.form).toString() }),
      // A redirect is a URL the guard never inspected. See the module header.
      redirect: "error",
      signal: AbortSignal.timeout(
        options.timeoutMs ?? DEFAULT_OUTBOUND_TIMEOUT_MS,
      ),
    });
  } catch (error) {
    // `fetch` reports a refused redirect as a generic TypeError, so the message
    // is the only signal available to distinguish it from a connection failure.
    const message = error instanceof Error ? error.message : String(error);
    return /redirect/i.test(message)
      ? refuse("redirected", `${raw} redirected, which is not followed`)
      : refuse("unreachable", `${raw} could not be fetched: ${message}`);
  }

  if (!response.ok) {
    // The body is included, truncated, because an OAuth refusal puts the reason
    // there and nowhere else - "the provider answered 400" sends an operator
    // hunting for something `invalid_grant` would have told them outright. It
    // reaches the audit trail, never the browser.
    const body = await readBounded(response, maxBytes);
    const detail =
      body === undefined || body.length === 0
        ? ""
        : `: ${body.slice(0, BAD_STATUS_BODY_CHARACTERS)}`;
    return refuse(
      "bad-status",
      `${raw} answered ${String(response.status)}${detail}`,
    );
  }

  const text = await readBounded(response, maxBytes);
  if (text === undefined) {
    return refuse(
      "too-large",
      `${raw} returned more than ${String(maxBytes)} bytes`,
    );
  }

  try {
    return { ok: true, value: JSON.parse(text) as T };
  } catch {
    return refuse("not-json", `${raw} did not return valid JSON`);
  }
}
