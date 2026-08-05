/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  ApiError,
  describeError,
  issuesByField,
  isUnauthenticated,
  toApiError,
} from "./errors.js";

describe("toApiError", () => {
  it("reads the code, message and issues", () => {
    const error = toApiError(400, {
      error: "invalid_request",
      message: "That request is not valid",
      issues: [{ path: "name", message: "Required" }],
    });

    expect(error.status).toBe(400);
    expect(error.code).toBe("invalid_request");
    expect(error.message).toBe("That request is not valid");
    expect(error.issues).toEqual([{ path: "name", message: "Required" }]);
  });

  it("survives a body that is not the expected shape", () => {
    // What a proxy returns when it, rather than the application, refuses.
    const error = toApiError(502, "<html>Bad gateway</html>");
    expect(error.code).toBe("error");
    expect(error.message).toContain("502");
    expect(error.issues).toEqual([]);
  });

  it("survives a null body", () => {
    expect(toApiError(500, null).message).toContain("500");
  });

  it("keeps a route-specific flag readable", () => {
    // The sign-in path answers `totpRequired` beside the standard fields, and the
    // console has to branch on it rather than on the message.
    const error = toApiError(401, {
      error: "unauthenticated",
      message: "This account requires a verification code",
      totpRequired: true,
    });
    expect(error.flag("totpRequired")).toBe(true);
    expect(error.flag("somethingElse")).toBe(false);
  });

  it("drops malformed issues rather than trusting them", () => {
    const error = toApiError(400, {
      error: "invalid_request",
      message: "no",
      issues: [{ path: "a", message: "b" }, "nonsense", { path: 1 }],
    });
    expect(error.issues).toEqual([{ path: "a", message: "b" }]);
  });
});

describe("issuesByField", () => {
  it("indexes by path", () => {
    const error = new ApiError(400, "invalid_request", "no", [
      { path: "name", message: "Required" },
      { path: "redirectUris.0", message: "Must be a URL" },
    ]);

    expect(issuesByField(error)).toEqual({
      name: "Required",
      "redirectUris.0": "Must be a URL",
    });
  });

  it("keeps the first message for a repeated field", () => {
    const error = new ApiError(400, "invalid_request", "no", [
      { path: "name", message: "First" },
      { path: "name", message: "Second" },
    ]);
    expect(issuesByField(error)["name"]).toBe("First");
  });

  it("is empty for anything that is not an API refusal", () => {
    expect(issuesByField(new Error("network"))).toEqual({});
    expect(issuesByField(undefined)).toEqual({});
  });
});

describe("describeError", () => {
  it("uses the API's message", () => {
    expect(describeError(new ApiError(409, "conflict", "Already taken"))).toBe(
      "Already taken",
    );
  });

  it("uses an ordinary error's message", () => {
    expect(describeError(new Error("Failed to fetch"))).toBe("Failed to fetch");
  });

  it("still says something for a thrown non-error", () => {
    expect(describeError("boom")).toContain("Something went wrong");
    expect(describeError(undefined)).toContain("Something went wrong");
  });

  it("falls back when an error carries no message", () => {
    // An `Error` with an empty message reaches the UI from a few libraries, and
    // rendering it would show the reader a blank alert.
    const empty = new Error("some message");
    empty.message = "";
    expect(describeError(empty)).toContain("Something went wrong");
  });
});

describe("isUnauthenticated", () => {
  it("recognises a 401", () => {
    expect(isUnauthenticated(new ApiError(401, "unauthenticated", "no"))).toBe(
      true,
    );
  });

  it("does not treat a 403 as being signed out", () => {
    // The person is signed in and lacks the authority; signing them out would be
    // an unhelpful answer to "you may not do that".
    expect(isUnauthenticated(new ApiError(403, "forbidden", "no"))).toBe(false);
  });

  it("does not treat a network failure as being signed out", () => {
    expect(isUnauthenticated(new Error("Failed to fetch"))).toBe(false);
  });
});
