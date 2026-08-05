/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  clientIdPrefix,
  generateClientId,
  generateClientSecret,
} from "./credentials.js";

describe("clientIdPrefix", () => {
  it("lower-cases and hyphenates a display name", () => {
    expect(clientIdPrefix("Growth Chart App")).toBe("growth-chart-app");
  });

  it("collapses runs of punctuation into one hyphen", () => {
    expect(clientIdPrefix("A -- B__C")).toBe("a-b-c");
  });

  it("trims leading and trailing hyphens", () => {
    expect(clientIdPrefix("  !Hello!  ")).toBe("hello");
  });

  it("falls back rather than producing an empty prefix", () => {
    expect(clientIdPrefix("测试")).toBe("client");
    expect(clientIdPrefix("")).toBe("client");
  });

  it("does not end in a hyphen after truncation", () => {
    // A name whose 33rd character is where the hyphen falls would otherwise
    // produce `...something-` and then `...something--suffix`.
    const prefix = clientIdPrefix(`${"a".repeat(32)} tail`);
    expect(prefix.endsWith("-")).toBe(false);
    expect(prefix).toBe("a".repeat(32));
  });
});

describe("generateClientId", () => {
  it("combines the derived prefix with a random suffix", () => {
    const id = generateClientId("Growth Chart App");
    expect(id.startsWith("growth-chart-app-")).toBe(true);
  });

  it("is URL-safe", () => {
    expect(generateClientId("Weird & Wonderful!")).toMatch(/^[a-z0-9-]+$/);
  });

  it("does not repeat", () => {
    const ids = new Set(
      Array.from({ length: 50 }, () => generateClientId("app")),
    );
    expect(ids.size).toBe(50);
  });
});

describe("generateClientSecret", () => {
  it("produces a long, unique value", () => {
    const first = generateClientSecret();
    expect(first.length).toBeGreaterThanOrEqual(32);
    expect(generateClientSecret()).not.toBe(first);
  });
});
