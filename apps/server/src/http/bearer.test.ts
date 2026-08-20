/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { bearerToken } from "./bearer.js";

describe("bearerToken", () => {
  it("returns undefined when there is no header", () => {
    expect(bearerToken(undefined)).toBeUndefined();
  });

  it("reads the token after the scheme", () => {
    expect(bearerToken("Bearer abc123")).toBe("abc123");
  });

  it("accepts the scheme in any case", () => {
    expect(bearerToken("bEaReR abc123")).toBe("abc123");
  });

  it("trims surrounding whitespace", () => {
    expect(bearerToken("Bearer   abc123  ")).toBe("abc123");
  });

  it("refuses a scheme it does not recognise", () => {
    expect(bearerToken("Basic dXNlcjpwYXNz")).toBeUndefined();
  });

  it("treats an empty credential as absent", () => {
    expect(bearerToken("Bearer   ")).toBeUndefined();
  });
});
