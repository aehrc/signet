/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Redirect URI matching.
 *
 * This is the check that keeps an authorization code from being delivered to an
 * attacker. It is an exact string comparison, with exactly one documented
 * exception, and the exception is deliberately narrow.
 *
 * Why exact rather than prefix: a prefix match on `https://app.example.org/cb`
 * accepts `https://app.example.org/cb.attacker.example/`, and a match that
 * ignores the query accepts a redirect carrying an attacker-controlled
 * parameter that the app then reflects. Both are live redirect-URI attacks, and
 * OAuth 2.1 removed every matching rule other than exact string equality for
 * this reason.
 *
 * The one exception is loopback port flexibility for native applications: a
 * desktop or mobile app that listens on an ephemeral port cannot know its port
 * at registration time, so RFC 8252 §7.3 requires the server to ignore the port
 * of a loopback redirect. It is restricted to `public` clients - a web
 * application with a client secret has a fixed redirect URI and has no business
 * pointing one at the user's own machine.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8252#section-7.3
 * @see https://datatracker.ietf.org/doc/html/rfc9700#section-2.1
 *
 * Author: John Grimes
 */

import { isScriptFreeUri } from "@signet/core";

import type { ClientType } from "@signet/core";

/** Hostnames RFC 8252 designates for a native app's loopback listener. */
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set([
  "127.0.0.1",
  "[::1]",
  // `localhost` is deliberately absent. RFC 8252 §8.3 recommends against it,
  // because it resolves through the name service and can be pointed elsewhere
  // by a hosts-file entry or a hostile resolver, where the literals cannot.
]);

/** Why a redirect URI was refused. */
export type RedirectUriRefusal =
  /** No `redirect_uri` was supplied. */
  | "missing"
  /** The value is not a parseable absolute URI. */
  | "malformed"
  /** The client has no registered redirect URIs at all. */
  | "none-registered"
  /** Parseable, but matching no registration. */
  | "no-match";

/** The outcome of matching a presented redirect URI against a registration. */
export type RedirectUriMatch =
  | {
      readonly ok: true;
      /**
       * The value to bind the authorization code to and to redirect with.
       *
       * This is the URI *as presented*, not the registration it matched. Under
       * loopback flexibility the two differ in their port, and the browser is
       * listening on the presented one.
       */
      readonly redirectUri: string;
      /** Whether the match relied on loopback port flexibility. */
      readonly loopback: boolean;
    }
  | { readonly ok: false; readonly reason: RedirectUriRefusal };

/**
 * Whether a URI is a loopback address eligible for port flexibility.
 *
 * Only `http` counts: RFC 8252 permits plain HTTP for the loopback interface
 * precisely because the traffic never leaves the machine, and an `https`
 * loopback URI has a certificate to be exact about.
 */
function isFlexibleLoopback(url: URL): boolean {
  // `hostname` carries the brackets for an IPv6 literal and excludes the port,
  // which is what makes the set above readable as written.
  return url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname);
}

/**
 * Compares two URIs for equality in every component except the port.
 *
 * Both must already be known loopback URIs. Scheme, host, path, query and
 * fragment must all agree - the port is the only latitude RFC 8252 grants.
 */
function equalIgnoringPort(presented: URL, registered: URL): boolean {
  return (
    presented.protocol === registered.protocol &&
    presented.hostname === registered.hostname &&
    presented.pathname === registered.pathname &&
    presented.search === registered.search &&
    presented.hash === registered.hash
  );
}

/**
 * Parses a URI, returning undefined rather than throwing.
 *
 * A relative reference is rejected: a redirect URI has to be absolute for the
 * comparison to mean anything, and `new URL` accepts a relative one only when
 * given a base, which is exactly the leniency to avoid here.
 */
function parseAbsolute(value: string): URL | undefined {
  try {
    const url = new URL(value);
    return url.protocol.length === 0 ? undefined : url;
  } catch {
    return undefined;
  }
}

/**
 * Matches a presented `redirect_uri` against a client's registrations.
 *
 * @param presented - The `redirect_uri` request parameter, if there was one.
 * @param registered - The client's registered redirect URIs.
 * @param clientType - Decides whether loopback port flexibility applies.
 */
export function matchRedirectUri(
  presented: string | undefined,
  registered: readonly string[],
  clientType: ClientType,
): RedirectUriMatch {
  if (presented === undefined || presented.length === 0) {
    return { ok: false, reason: "missing" };
  }
  if (registered.length === 0) {
    return { ok: false, reason: "none-registered" };
  }

  // Exact equality is tried against the raw strings, before any parsing. Two
  // URIs that differ only in percent-encoding are different strings and must not
  // match here: normalising first would reintroduce the ambiguity this check
  // exists to remove.
  if (registered.includes(presented)) {
    // A registration recorded before the contract refused script-executing
    // schemes must not be revived by the exact-string match: following it would
    // run attacker script on Signet's own origin, where the user's session is.
    if (!isScriptFreeUri(presented)) {
      return { ok: false, reason: "no-match" };
    }
    return { ok: true, redirectUri: presented, loopback: false };
  }

  const presentedUrl = parseAbsolute(presented);
  if (presentedUrl === undefined) {
    return { ok: false, reason: "malformed" };
  }

  if (clientType !== "public" || !isFlexibleLoopback(presentedUrl)) {
    return { ok: false, reason: "no-match" };
  }

  for (const candidate of registered) {
    const registeredUrl = parseAbsolute(candidate);
    if (
      registeredUrl !== undefined &&
      isFlexibleLoopback(registeredUrl) &&
      equalIgnoringPort(presentedUrl, registeredUrl)
    ) {
      return { ok: true, redirectUri: presented, loopback: true };
    }
  }

  return { ok: false, reason: "no-match" };
}
