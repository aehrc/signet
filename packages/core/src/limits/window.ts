/**
 * Sliding-window rate limiting, as arithmetic.
 *
 * Pure, so the awkward parts are testable without a clock or a server: what
 * happens at the boundary between two windows, what a burst of simultaneous
 * requests does, and whether a caller who waits exactly long enough is admitted.
 *
 * The algorithm is a two-window approximation rather than a fixed window or a
 * full log of timestamps, and the choice matters. A fixed window admits twice the
 * limit across a boundary - a caller who spends their whole allowance in the last
 * second of one window and again in the first second of the next - which for a
 * token endpoint means twice the guessing rate at a predictable moment. A log of
 * every request timestamp is exact but grows with traffic, which is the wrong
 * shape for something that runs in front of every request.
 *
 * So each key keeps two counters: the current window's, and the previous one's.
 * The estimate weights the previous window by how much of it still overlaps the
 * trailing period. A caller at a steady rate sees a steady limit, and the
 * boundary doubling is gone. The approximation errs slightly high inside a window
 * when traffic is bursty, which is the direction that refuses rather than admits.
 *
 * Nothing here is aware of processes or replicas. That is the caller's problem and
 * it is a real one: see the server's rate-limit middleware for what a deployment
 * with several replicas actually gets.
 */

/** What a key's counters look like between requests. */
export interface WindowState {
  /** Start of the current window, in epoch milliseconds. */
  readonly windowStart: number;
  /** Requests counted in the current window. */
  readonly current: number;
  /** Requests counted in the window before it. */
  readonly previous: number;
}

/** How much a key may do, and over what period. */
export interface WindowLimit {
  readonly limit: number;
  readonly windowMs: number;
}

/** What a request costs a key, and what the caller should be told. */
export interface WindowDecision {
  readonly allowed: boolean;
  /** The state to store back. Always advances, admitted or not. */
  readonly state: WindowState;
  /** How many more requests this key may make in the window, at best. */
  readonly remaining: number;
  /**
   * When the caller should try again, in epoch milliseconds.
   *
   * The end of the current window. Not a precise moment at which the estimate
   * falls below the limit - that would tell a caller exactly how to pace their
   * guessing, and the whole window is a fine thing to ask them to wait.
   */
  readonly retryAt: number;
}

/** A key that has never been seen. */
export function emptyWindow(now: number, windowMs: number): WindowState {
  return { windowStart: alignWindow(now, windowMs), current: 0, previous: 0 };
}

/** The start of the window a moment falls in. */
function alignWindow(now: number, windowMs: number): number {
  return Math.floor(now / windowMs) * windowMs;
}

/**
 * Rolls a key's state forward to the window `now` falls in.
 *
 * One window on, the current count becomes the previous one. Two or more, both
 * are dropped: a caller who has been silent for two whole windows is
 * indistinguishable from one who has never been seen, and treating them
 * differently would keep state for every address that ever made a request.
 */
function rollForward(
  state: WindowState,
  now: number,
  windowMs: number,
): WindowState {
  const windowStart = alignWindow(now, windowMs);
  const elapsed = windowStart - state.windowStart;
  if (elapsed <= 0) {
    return state;
  }
  if (elapsed === windowMs) {
    return { windowStart, current: 0, previous: state.current };
  }
  return { windowStart, current: 0, previous: 0 };
}

/**
 * The weighted count for a key, without recording a request.
 *
 * The previous window contributes in proportion to how much of it is still inside
 * the trailing window: at the very start of a window it counts almost in full, and
 * by the end it counts for nothing.
 *
 * @param state - The key's counters, already rolled forward.
 * @param now - The current time, in epoch milliseconds.
 * @param windowMs - The window length.
 */
export function weightedCount(
  state: WindowState,
  now: number,
  windowMs: number,
): number {
  const elapsed = now - state.windowStart;
  const overlap = Math.max(0, Math.min(1, 1 - elapsed / windowMs));
  return state.current + state.previous * overlap;
}

/**
 * Decides whether a request is admitted, and returns the state to store.
 *
 * A refused request still increments the counter. That is deliberate: a caller
 * hammering a limited endpoint should not be able to keep their estimate below the
 * threshold by being refused, and the alternative admits a request every time the
 * window rolls regardless of how hard they are pushing.
 *
 * @param state - The key's counters, or undefined for a key never seen.
 * @param now - The current time, in epoch milliseconds.
 * @param limit - How much the key may do, and over what period.
 */
export function admitRequest(
  state: WindowState | undefined,
  now: number,
  limit: WindowLimit,
): WindowDecision {
  const rolled = rollForward(
    state ?? emptyWindow(now, limit.windowMs),
    now,
    limit.windowMs,
  );
  const estimate = weightedCount(rolled, now, limit.windowMs);
  const next: WindowState = { ...rolled, current: rolled.current + 1 };

  return {
    allowed: estimate < limit.limit,
    state: next,
    remaining: Math.max(0, Math.floor(limit.limit - estimate - 1)),
    retryAt: rolled.windowStart + limit.windowMs,
  };
}

/**
 * Whether a key's state can be forgotten.
 *
 * True once two whole windows have passed with nothing recorded, which is exactly
 * when {@link rollForward} would reset it to empty anyway. The sweep that uses
 * this is what keeps an in-memory store from growing once per address that ever
 * made a request.
 *
 * @param state - The key's counters.
 * @param now - The current time, in epoch milliseconds.
 * @param windowMs - The window length.
 */
export function isWindowStale(
  state: WindowState,
  now: number,
  windowMs: number,
): boolean {
  return now - state.windowStart >= windowMs * 2;
}
