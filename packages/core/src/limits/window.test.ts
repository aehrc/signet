/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  admitRequest,
  emptyWindow,
  isWindowStale,
  weightedCount,
} from "./window.js";

import type { WindowLimit, WindowState } from "./window.js";

const LIMIT: WindowLimit = { limit: 5, windowMs: 60_000 };

/** Makes `count` requests from a starting state, all at the same instant. */
function burst(
  state: WindowState | undefined,
  now: number,
  count: number,
  limit: WindowLimit = LIMIT,
): { readonly state: WindowState | undefined; readonly admitted: number } {
  let current = state;
  let admitted = 0;
  for (let index = 0; index < count; index += 1) {
    const decision = admitRequest(current, now, limit);
    current = decision.state;
    if (decision.allowed) {
      admitted += 1;
    }
  }
  return { state: current, admitted };
}

describe("admitRequest", () => {
  it("admits exactly the limit in an empty window", () => {
    expect(burst(undefined, 0, 10).admitted).toBe(5);
  });

  it("counts a refused request, so pushing harder does not help", () => {
    const pushed = burst(undefined, 0, 50);
    // Still refused a moment later: the refusals were counted, so the estimate
    // did not stay pinned at the threshold.
    expect(admitRequest(pushed.state, 1000, LIMIT).allowed).toBe(false);
  });

  it("reports how many remain", () => {
    let state: WindowState | undefined;
    const remaining: number[] = [];
    for (let index = 0; index < 5; index += 1) {
      const decision = admitRequest(state, 0, LIMIT);
      state = decision.state;
      remaining.push(decision.remaining);
    }
    expect(remaining).toEqual([4, 3, 2, 1, 0]);
  });

  it("tells the caller when the window ends", () => {
    const decision = admitRequest(undefined, 90_000, LIMIT);
    expect(decision.retryAt).toBe(120_000);
  });

  it("does not admit twice the limit across a window boundary", () => {
    // The failure a fixed window has: spend the allowance at the end of one
    // window and again at the start of the next.
    const first = burst(undefined, 59_000, 10);
    expect(first.admitted).toBe(5);

    const second = burst(first.state, 60_500, 10);
    // A fixed-window counter would admit five more here. The weighted estimate
    // still counts almost all of the previous window, so it admits none.
    expect(second.admitted).toBe(0);
  });

  it("lets the previous window decay as the current one runs", () => {
    const spent = burst(undefined, 0, 5);
    // Nine tenths of the way through the next window, only a tenth of the
    // previous window's five still counts.
    const late = burst(spent.state, 114_000, 10);
    expect(late.admitted).toBeGreaterThan(3);
    expect(late.admitted).toBeLessThanOrEqual(5);
  });

  it("forgets a caller silent for two windows", () => {
    const spent = burst(undefined, 0, 5);
    expect(burst(spent.state, 150_000, 10).admitted).toBe(5);
  });

  it("treats a zero limit as admitting nothing", () => {
    expect(
      admitRequest(undefined, 0, { limit: 0, windowMs: 60_000 }).allowed,
    ).toBe(false);
  });
});

describe("weightedCount", () => {
  it("counts the whole previous window at the start of a new one", () => {
    const state: WindowState = {
      windowStart: 60_000,
      current: 0,
      previous: 4,
    };
    expect(weightedCount(state, 60_000, 60_000)).toBe(4);
  });

  it("counts none of it at the end", () => {
    const state: WindowState = {
      windowStart: 60_000,
      current: 1,
      previous: 4,
    };
    expect(weightedCount(state, 120_000, 60_000)).toBe(1);
  });

  it("counts half of it in the middle", () => {
    const state: WindowState = {
      windowStart: 60_000,
      current: 1,
      previous: 4,
    };
    expect(weightedCount(state, 90_000, 60_000)).toBe(3);
  });
});

describe("isWindowStale", () => {
  it("is false inside the window and the one after", () => {
    const state = emptyWindow(0, 60_000);
    expect(isWindowStale(state, 30_000, 60_000)).toBe(false);
    expect(isWindowStale(state, 119_000, 60_000)).toBe(false);
  });

  it("is true once two windows have passed", () => {
    const state = emptyWindow(0, 60_000);
    expect(isWindowStale(state, 120_000, 60_000)).toBe(true);
  });
});
