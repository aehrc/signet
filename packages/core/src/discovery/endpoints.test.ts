/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { endpointUrls, normaliseIssuer } from "./endpoints.js";

import type { EndpointUrls } from "./endpoints.js";

const ISSUER = "https://signet.example.com/t/acme";

describe("normaliseIssuer", () => {
  it("leaves an issuer without a trailing slash alone", () => {
    expect(normaliseIssuer(ISSUER)).toBe(ISSUER);
  });

  it("strips a single trailing slash", () => {
    expect(normaliseIssuer(`${ISSUER}/`)).toBe(ISSUER);
  });

  it("strips repeated trailing slashes", () => {
    expect(normaliseIssuer(`${ISSUER}///`)).toBe(ISSUER);
  });

  it("does not touch slashes inside the issuer", () => {
    expect(normaliseIssuer("https://example.com/a/b/c")).toBe(
      "https://example.com/a/b/c",
    );
  });

  it("reduces a bare origin with a slash to the origin", () => {
    expect(normaliseIssuer("https://example.com/")).toBe("https://example.com");
  });
});

/** Every derived URL, listed explicitly so the assertions stay type-safe. */
function allUrls(urls: EndpointUrls): readonly string[] {
  return [
    urls.authorization,
    urls.token,
    urls.jwks,
    urls.introspection,
    urls.revocation,
    urls.userinfo,
    urls.registration,
    urls.management,
    urls.launchContext,
    urls.smartConfiguration,
    urls.openIdConfiguration,
  ];
}

describe("endpointUrls", () => {
  it("derives every endpoint from the issuer", () => {
    expect(endpointUrls(ISSUER)).toEqual({
      authorization: `${ISSUER}/authorize`,
      token: `${ISSUER}/token`,
      jwks: `${ISSUER}/jwks`,
      introspection: `${ISSUER}/introspect`,
      revocation: `${ISSUER}/revoke`,
      userinfo: `${ISSUER}/userinfo`,
      registration: `${ISSUER}/register`,
      management: `${ISSUER}/manage`,
      launchContext: `${ISSUER}/launch-context`,
      smartConfiguration: `${ISSUER}/.well-known/smart-configuration`,
      openIdConfiguration: `${ISSUER}/.well-known/openid-configuration`,
    });
  });

  it("produces identical URLs whether or not the issuer has a trailing slash", () => {
    expect(endpointUrls(`${ISSUER}/`)).toEqual(endpointUrls(ISSUER));
  });

  it("never produces a double slash in the path", () => {
    for (const issuer of [ISSUER, `${ISSUER}/`, `${ISSUER}//`]) {
      for (const url of allUrls(endpointUrls(issuer))) {
        expect(url.slice("https://".length)).not.toContain("//");
      }
    }
  });

  it("puts the well-known documents under the issuer, not the origin", () => {
    const urls = endpointUrls(ISSUER);
    expect(urls.smartConfiguration).toBe(
      "https://signet.example.com/t/acme/.well-known/smart-configuration",
    );
    expect(urls.openIdConfiguration).toBe(
      "https://signet.example.com/t/acme/.well-known/openid-configuration",
    );
  });

  it("returns every key with a non-empty string value", () => {
    const urls = endpointUrls(ISSUER);
    expect(Object.keys(urls)).toHaveLength(allUrls(urls).length);
    for (const url of allUrls(urls)) {
      expect(url).toMatch(/^https:\/\/\S+$/);
    }
  });
});
