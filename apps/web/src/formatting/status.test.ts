/**
 * Author: John Grimes
 */

import { describe, expect, it } from "vitest";

import { toneForStatus } from "./status.js";

describe("toneForStatus", () => {
  it("reads an active thing as good", () => {
    expect(toneForStatus("active")).toBe("success");
  });

  it("reads an approved request as good", () => {
    // The developer portal and the console both show a request's review state, and a
    // black badge for "approved" reads as neutral news rather than good.
    expect(toneForStatus("approved")).toBe("success");
  });

  it("reads a queued thing as informational", () => {
    expect(toneForStatus("next")).toBe("info");
    expect(toneForStatus("pending")).toBe("info");
  });

  it("reads a withdrawn thing as a warning", () => {
    expect(toneForStatus("suspended")).toBe("warning");
    expect(toneForStatus("disabled")).toBe("warning");
  });

  it("reads a refusal as bad", () => {
    expect(toneForStatus("rejected")).toBe("error");
  });

  it("does not invent a problem for a status it does not know", () => {
    // A rolling upgrade can serve a state this bundle has never heard of.
    expect(toneForStatus("something-new")).toBe("neutral");
  });
});
