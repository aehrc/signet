/**
 * Rate limiting on the endpoints where guessing pays.
 *
 * Four of them, and each is limited because a specific attack against it is cheap
 * otherwise: the token endpoint (a client secret, or an authorization code), the
 * two sign-in surfaces (a person's password), and `/authorize` (session creation,
 * which writes a row per request and is reachable without any credential at all).
 *
 * **What a deployment actually gets.** The counters are in this process's memory.
 * With `n` replicas behind a load balancer the effective limit is up to `n` times
 * what is configured, because a caller's requests are spread across them. That is
 * a deliberate trade rather than an oversight: a shared counter means a round trip
 * to Postgres or Redis in front of every request to the busiest endpoints, and the
 * threat this defends against - online guessing - is still defeated by a limit
 * that is off by a small integer factor. A deployment that needs an exact global
 * limit should put it at the ingress, which is where that control belongs.
 *
 * What this is *not* is a defence against a distributed flood. A limiter keyed by
 * address does nothing against ten thousand addresses, and nothing here pretends
 * otherwise; that is a job for the layer in front.
 *
 * **What the key is.** The client address and the route, and nothing from the
 * request body. Keying on a username would let an attacker spread guesses across
 * usernames to stay under the limit, and keying on a client identifier would let
 * an unauthenticated caller exhaust another client's allowance by naming it.
 *
 * The address comes from `requestMetadata`, which reads `X-Forwarded-For` - so a
 * deployment that does not strip that header at its ingress is one where a caller
 * chooses their own key. That is true of the audit trail too, and is documented
 * where the header is read.
 */

import { admitRequest, isWindowStale } from "@signet/core";

import { requestMetadata } from "./requestMeta.js";

import type { WindowLimit, WindowState } from "@signet/core";
import type { Context, MiddlewareHandler } from "hono";

/**
 * How often the store is swept for keys nobody has used.
 *
 * Every two hundred requests rather than on a timer: a timer keeps the process
 * awake and has to be cleared in tests, and a counter sweeps in proportion to the
 * traffic that is filling the map in the first place.
 */
const SWEEP_EVERY = 200;

/** The limits, per client address, for each protected route. */
export const RATE_LIMITS = {
  /**
   * The token endpoint. Generous enough for a busy backend service refreshing
   * tokens, tight enough that a client secret cannot be guessed online.
   */
  token: { limit: 60, windowMs: 60_000 },
  /** `/authorize`. Every request writes a session row. */
  authorize: { limit: 60, windowMs: 60_000 },
  /**
   * Signing in - an end user's password, or an administrator's.
   *
   * Ten a minute. A person who has mistyped their password ten times in a minute
   * is not going to get it right on the eleventh, and an attacker gets ten
   * guesses a minute per address against an Argon2id hash.
   */
  signIn: { limit: 10, windowMs: 60_000 },
} as const satisfies Readonly<Record<string, WindowLimit>>;

/** Which limit a route is under. */
export type RateLimitName = keyof typeof RATE_LIMITS;

/** The counters for one process. */
export interface RateLimitStore {
  readonly check: (
    key: string,
    now: number,
    limit: WindowLimit,
  ) => ReturnType<typeof admitRequest>;
  /** How many keys are held. Exposed for the tests and for a health page. */
  readonly size: () => number;
}

/**
 * Builds an in-memory store.
 *
 * Exported so a test can hold one rather than sharing the process-wide store, and
 * so the sweep can be asserted on directly.
 */
export function createRateLimitStore(): RateLimitStore {
  const windows = new Map<string, WindowState>();
  let sinceSweep = 0;

  /** Drops keys that {@link admitRequest} would treat as new anyway. */
  const sweep = (now: number, windowMs: number): void => {
    for (const [key, state] of windows) {
      if (isWindowStale(state, now, windowMs)) {
        windows.delete(key);
      }
    }
  };

  return {
    check: (key, now, limit) => {
      sinceSweep += 1;
      if (sinceSweep >= SWEEP_EVERY) {
        sinceSweep = 0;
        sweep(now, limit.windowMs);
      }
      const decision = admitRequest(windows.get(key), now, limit);
      windows.set(key, decision.state);
      return decision;
    },
    size: () => windows.size,
  };
}

/**
 * A store that admits everything.
 *
 * For the test harness, and for nothing else. The suites drive hundreds of
 * sign-ins against a frozen clock, which is exactly the traffic the limiter exists
 * to refuse - so they opt out of it, and the limiter is proved by its own tests
 * instead, plus one integration test that opts back in.
 */
export function createUnlimitedStore(): RateLimitStore {
  return {
    check: (_key, now, limit) => ({
      allowed: true,
      state: { windowStart: now, current: 0, previous: 0 },
      remaining: limit.limit,
      retryAt: now + limit.windowMs,
    }),
    size: () => 0,
  };
}

/**
 * The key a request is counted against.
 *
 * An address that could not be determined - which happens in tests, and behind a
 * proxy that strips everything - collapses to one bucket named `unknown`. That is
 * the conservative choice: it limits those callers collectively rather than
 * exempting them.
 */
function rateLimitKey(c: Context, name: RateLimitName): string {
  return `${name}:${requestMetadata(c).ip ?? "unknown"}`;
}

/** How a refusal is worded on an OAuth endpoint. */
const REFUSAL = {
  error: "slow_down",
  error_description: "Too many requests. Try again shortly.",
} as const;

/**
 * Limits a route by client address.
 *
 * The response carries `Retry-After` and the `RateLimit-*` headers, because a
 * well-behaved client should be able to back off without guessing, and a badly
 * behaved one is going to be refused either way.
 *
 * `slow_down` rather than `invalid_request`: RFC 8628 gives it exactly this
 * meaning, and a client library that understands it will wait rather than treat
 * the refusal as a permanent failure of the credential it just sent.
 *
 * @param name - Which limit to apply.
 * @param clock - Reads the current time. Injected so tests need no real one.
 * @param store - The counters to use. One per application; see `ServerContext`.
 */
export function rateLimit(
  name: RateLimitName,
  clock: () => Date,
  store: RateLimitStore,
): MiddlewareHandler {
  const limit = RATE_LIMITS[name];
  return async (c, next) => {
    const now = clock().getTime();
    const decision = store.check(rateLimitKey(c, name), now, limit);

    c.header("RateLimit-Limit", String(limit.limit));
    c.header("RateLimit-Remaining", String(decision.remaining));
    c.header(
      "RateLimit-Reset",
      String(Math.max(0, Math.ceil((decision.retryAt - now) / 1000))),
    );

    if (!decision.allowed) {
      c.header(
        "Retry-After",
        String(Math.max(1, Math.ceil((decision.retryAt - now) / 1000))),
      );
      return c.json(REFUSAL, 429);
    }

    await next();
    return;
  };
}
