/**
 * Author: John Grimes
 */

import { describe, expect, it } from "vitest";

import { matchRedirectUri } from "./redirectUri.js";

const WEB = ["https://app.example.org/callback"];

describe("matchRedirectUri", () => {
  it("accepts an exact match", () => {
    expect(
      matchRedirectUri("https://app.example.org/callback", WEB, "public"),
    ).toEqual({
      ok: true,
      redirectUri: "https://app.example.org/callback",
      loopback: false,
    });
  });

  it("refuses a missing redirect URI", () => {
    expect(matchRedirectUri(undefined, WEB, "public")).toEqual({
      ok: false,
      reason: "missing",
    });
    expect(matchRedirectUri("", WEB, "public")).toEqual({
      ok: false,
      reason: "missing",
    });
  });

  it("refuses a client with no registered redirect URIs", () => {
    expect(
      matchRedirectUri("https://app.example.org/callback", [], "public"),
    ).toEqual({ ok: false, reason: "none-registered" });
  });

  it("refuses a prefix of a registered URI", () => {
    expect(
      matchRedirectUri("https://app.example.org/call", WEB, "public").ok,
    ).toBe(false);
  });

  it("refuses a registered URI used as a prefix", () => {
    expect(
      matchRedirectUri(
        "https://app.example.org/callback.attacker.example/",
        WEB,
        "public",
      ).ok,
    ).toBe(false);
  });

  it("refuses an added query parameter", () => {
    expect(
      matchRedirectUri(
        "https://app.example.org/callback?next=https://attacker.example",
        WEB,
        "public",
      ).ok,
    ).toBe(false);
  });

  it("refuses an added fragment", () => {
    expect(
      matchRedirectUri("https://app.example.org/callback#x", WEB, "public").ok,
    ).toBe(false);
  });

  it("refuses a differing host", () => {
    expect(
      matchRedirectUri("https://app.example.com/callback", WEB, "public").ok,
    ).toBe(false);
  });

  it("refuses a differing scheme", () => {
    expect(
      matchRedirectUri("http://app.example.org/callback", WEB, "public").ok,
    ).toBe(false);
  });

  it("refuses a value that is not an absolute URI", () => {
    expect(matchRedirectUri("/callback", WEB, "public")).toEqual({
      ok: false,
      reason: "malformed",
    });
  });

  it("matches a custom scheme exactly", () => {
    const registered = ["org.example.app:/oauth"];
    expect(
      matchRedirectUri("org.example.app:/oauth", registered, "public"),
    ).toEqual({
      ok: true,
      redirectUri: "org.example.app:/oauth",
      loopback: false,
    });
    expect(
      matchRedirectUri("org.example.app:/other", registered, "public").ok,
    ).toBe(false);
  });

  describe("loopback port flexibility", () => {
    const native = ["http://127.0.0.1:0/callback"];

    it("accepts a different port for a public client", () => {
      expect(
        matchRedirectUri("http://127.0.0.1:53535/callback", native, "public"),
      ).toEqual({
        ok: true,
        redirectUri: "http://127.0.0.1:53535/callback",
        loopback: true,
      });
    });

    it("returns the presented URI, not the registered one", () => {
      const match = matchRedirectUri(
        "http://127.0.0.1:53535/callback",
        native,
        "public",
      );
      expect(match.ok && match.redirectUri).toBe(
        "http://127.0.0.1:53535/callback",
      );
    });

    it("accepts the IPv6 loopback literal", () => {
      expect(
        matchRedirectUri(
          "http://[::1]:53535/callback",
          ["http://[::1]/callback"],
          "public",
        ).ok,
      ).toBe(true);
    });

    it("refuses flexibility for a confidential client", () => {
      expect(
        matchRedirectUri(
          "http://127.0.0.1:53535/callback",
          native,
          "confidential-symmetric",
        ),
      ).toEqual({ ok: false, reason: "no-match" });
      expect(
        matchRedirectUri(
          "http://127.0.0.1:53535/callback",
          native,
          "confidential-asymmetric",
        ).ok,
      ).toBe(false);
    });

    it("refuses a differing path even on loopback", () => {
      expect(
        matchRedirectUri("http://127.0.0.1:53535/other", native, "public").ok,
      ).toBe(false);
    });

    it("refuses a differing query even on loopback", () => {
      expect(
        matchRedirectUri(
          "http://127.0.0.1:53535/callback?x=1",
          native,
          "public",
        ).ok,
      ).toBe(false);
    });

    it("does not extend flexibility to localhost", () => {
      expect(
        matchRedirectUri(
          "http://localhost:53535/callback",
          ["http://localhost:1234/callback"],
          "public",
        ).ok,
      ).toBe(false);
    });

    it("does not extend flexibility to a non-loopback host", () => {
      expect(
        matchRedirectUri(
          "http://10.0.0.5:53535/callback",
          ["http://10.0.0.5:1234/callback"],
          "public",
        ).ok,
      ).toBe(false);
    });

    it("does not extend flexibility to an https loopback URI", () => {
      expect(
        matchRedirectUri(
          "https://127.0.0.1:53535/callback",
          ["https://127.0.0.1:1234/callback"],
          "public",
        ).ok,
      ).toBe(false);
    });
  });
});
