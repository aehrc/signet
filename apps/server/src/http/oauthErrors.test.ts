/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  authorizeErrorRedirect,
  oauthErrorBody,
  statusForTokenError,
} from "./oauthErrors.js";

describe("oauthErrorBody", () => {
  it("omits the description when there is none", () => {
    expect(oauthErrorBody("invalid_grant")).toEqual({ error: "invalid_grant" });
  });

  it("includes the description when given", () => {
    expect(oauthErrorBody("invalid_grant", "code expired")).toEqual({
      error: "invalid_grant",
      error_description: "code expired",
    });
  });
});

describe("statusForTokenError", () => {
  it("answers 401 for a client authentication failure", () => {
    expect(statusForTokenError("invalid_client")).toBe(401);
  });

  it.each([
    "invalid_request",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
  ] as const)("answers 400 for %s", (code) => {
    expect(statusForTokenError(code)).toBe(400);
  });
});

describe("authorizeErrorRedirect", () => {
  it("puts the error in the query string", () => {
    const location = authorizeErrorRedirect(
      "https://app.example.org/cb",
      "invalid_scope",
      "patient/Observation.q is not a scope",
      "xyz",
    );

    const url = new URL(location);
    expect(url.origin + url.pathname).toBe("https://app.example.org/cb");
    expect(url.searchParams.get("error")).toBe("invalid_scope");
    expect(url.searchParams.get("error_description")).toBe(
      "patient/Observation.q is not a scope",
    );
    expect(url.searchParams.get("state")).toBe("xyz");
    expect(url.hash).toBe("");
  });

  it("preserves query parameters already on the redirect URI", () => {
    const location = authorizeErrorRedirect(
      "https://app.example.org/cb?tenant=demo",
      "access_denied",
    );

    const url = new URL(location);
    expect(url.searchParams.get("tenant")).toBe("demo");
    expect(url.searchParams.get("error")).toBe("access_denied");
  });

  it("omits state and description when the request had neither", () => {
    const url = new URL(
      authorizeErrorRedirect("https://app.example.org/cb", "server_error"),
    );
    expect(url.searchParams.has("state")).toBe(false);
    expect(url.searchParams.has("error_description")).toBe(false);
  });
});
