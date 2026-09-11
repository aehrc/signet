/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Judging URIs that reach a browser.
 *
 * Three surfaces decide whether a URI may be followed, and they must agree:
 * client registration (through the contracts, at create, patch and approval),
 * the redirect match at `/authorize`, which also sees registrations recorded
 * before the rule existed, and a vouched registration's metadata. One module
 * here is the whole point - a second definition of "safe" is a drift waiting to
 * be a stored cross-site script.
 *
 * Author: John Grimes
 */

/**
 * Schemes whose navigation executes script or renders attacker-chosen content in
 * the browser that follows the link. A URI of one of these schemes must never be
 * accepted as a redirect or rendered as a link: the origin that follows it is
 * Signet's own, and script running there holds the user's session.
 */
const SCRIPT_SCHEMES: Readonly<Record<string, true>> = {
  "javascript:": true,
  "data:": true,
  "vbscript:": true,
  "blob:": true,
};

/**
 * The schemes the WHATWG URL parser treats as special: those with a hierarchical
 * host. A scheme outside this set and outside {@link SCRIPT_SCHEMES} is a
 * private-use scheme, which is how an RFC 8252 native app receives its redirect.
 */
const SPECIAL_SCHEMES: Readonly<Record<string, true>> = {
  "http:": true,
  "https:": true,
  "ws:": true,
  "wss:": true,
  "ftp:": true,
  "file:": true,
};

/** Hostnames an RFC 8252 loopback redirect may name. */
const LOOPBACK_HOSTS: Readonly<Record<string, true>> = {
  "127.0.0.1": true,
  "[::1]": true,
  localhost: true,
};

/**
 * Whether following a URI would execute script or render inline content.
 *
 * @param value - The URI to judge.
 * @returns False for `javascript:`, `data:`, `vbscript:` and `blob:` URIs, which
 *   a browser executes or renders rather than merely navigating to, and for
 *   anything that is not a parseable absolute URL at all.
 * @example
 * ```ts
 * isScriptFreeUri("javascript:alert(1)"); // false
 * isScriptFreeUri("org.example.app:/oauth"); // true
 * isScriptFreeUri("https://app.example.org/callback"); // true
 * ```
 */
export function isScriptFreeUri(value: string): boolean {
  try {
    return !SCRIPT_SCHEMES[new URL(value).protocol];
  } catch {
    return false;
  }
}

/**
 * Whether a URI is one a browser may be sent to or render.
 *
 * @param value - The URI to judge.
 * @returns True for `https:` and `http:` URIs only; anything that executes in
 *   the browser, and every other scheme, is refused.
 * @example
 * ```ts
 * isWebUri("https://app.example.org/launch"); // true
 * isWebUri("http://intranet.example.org/launch"); // true
 * isWebUri("javascript:alert(1)"); // false
 * ```
 */
export function isWebUri(value: string): boolean {
  try {
    const protocol = new URL(value).protocol;
    return protocol === "https:" || protocol === "http:";
  } catch {
    return false;
  }
}

/**
 * Whether a URI may be registered as an OAuth redirect URI.
 *
 * `https`, plain `http` on an RFC 8252 loopback address, and private-use schemes
 * - what a native app registers - are accepted. Everything that executes in the
 * browser, and everything else with a special scheme, is refused.
 *
 * @param value - The URI to judge.
 * @example
 * ```ts
 * isRegisterableRedirectUri("https://app.example.org/callback"); // true
 * isRegisterableRedirectUri("http://127.0.0.1:9000/callback"); // true
 * isRegisterableRedirectUri("org.example.app:/oauth"); // true
 * isRegisterableRedirectUri("javascript:alert(1)"); // false
 * isRegisterableRedirectUri("http://app.example.org/callback"); // false
 * ```
 */
export function isRegisterableRedirectUri(value: string): boolean {
  if (!isScriptFreeUri(value)) {
    return false;
  }
  try {
    const url = new URL(value);
    if (url.protocol === "https:") {
      return true;
    }
    if (url.protocol === "http:") {
      return LOOPBACK_HOSTS[url.hostname] === true;
    }
    return SPECIAL_SCHEMES[url.protocol] !== true;
  } catch {
    return false;
  }
}
