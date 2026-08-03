import { describe, expect, it } from "vitest";

import {
  clearedSessionCookie,
  cookiesAreSecure,
  readCookie,
  SESSION_COOKIE_NAME,
  sessionCookie,
} from "./cookies.js";

describe("readCookie", () => {
  it("returns undefined when there is no header", () => {
    expect(readCookie(undefined, "a")).toBeUndefined();
  });

  it("reads a single cookie", () => {
    expect(readCookie("a=1", "a")).toBe("1");
  });

  it("reads a cookie from the middle of a list", () => {
    expect(readCookie("x=0; a=1; y=2", "a")).toBe("1");
  });

  it("keeps a value containing an equals sign intact", () => {
    expect(readCookie("a=abc==", "a")).toBe("abc==");
  });

  it("takes the first occurrence of a repeated name", () => {
    expect(readCookie("a=first; a=second", "a")).toBe("first");
  });

  it("ignores a pair with no separator", () => {
    expect(readCookie("broken; a=1", "a")).toBe("1");
  });

  it("treats an empty value as absent", () => {
    expect(readCookie("a=", "a")).toBeUndefined();
  });

  it("does not match a name by prefix", () => {
    expect(readCookie("ab=1", "a")).toBeUndefined();
  });
});

describe("cookiesAreSecure", () => {
  it("is true for an https deployment", () => {
    expect(cookiesAreSecure("https://signet.example.org")).toBe(true);
  });

  it("is false for local development over http", () => {
    expect(cookiesAreSecure("http://localhost:3000")).toBe(false);
  });
});

describe("sessionCookie", () => {
  it("is httpOnly, lax and path-wide", () => {
    const cookie = sessionCookie("token", { secure: true });
    expect(cookie).toContain(`${SESSION_COOKIE_NAME}=token`);
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).toContain("Path=/");
    expect(cookie).toContain("Secure");
  });

  it("omits Secure when the deployment is not on https", () => {
    expect(sessionCookie("token", { secure: false })).not.toContain("Secure");
  });

  it("honours an explicit lifetime", () => {
    expect(sessionCookie("t", { secure: false, maxAgeSeconds: 60 })).toContain(
      "Max-Age=60",
    );
  });
});

describe("clearedSessionCookie", () => {
  it("expires immediately and matches the attributes it replaces", () => {
    const cleared = clearedSessionCookie({ secure: true });
    expect(cleared).toContain("Max-Age=0");
    expect(cleared).toContain("Path=/");
    expect(cleared).toContain("HttpOnly");
    expect(cleared).toContain("SameSite=Lax");
    expect(cleared).toContain("Secure");
  });
});
