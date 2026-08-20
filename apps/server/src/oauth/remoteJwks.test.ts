/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Resolving a trust anchor's published keys.
 *
 * Exercised against a real anchor on a real socket rather than against a stubbed
 * `fetch`, because two of the four properties are only observable that way. That
 * the guard is in the path is observable as a loopback address being refused - a
 * bare `fetch` would succeed. That the cache is caching is observable only as the
 * absence of a request, which means counting what the anchor actually served.
 *
 * The anchor binds loopback, so every test that expects a fetch to succeed passes
 * `allowPrivateAddresses`. That is not the guard being worked around: the first
 * test asserts the refusal without it, so the flag is the thing being switched
 * rather than the check being bypassed.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  createRemoteJwksCache,
  REMOTE_JWKS_MAX_AGE_SECONDS,
  resolveRemoteJwks,
} from "./remoteJwks.js";
import { jsonResponse, startLocalListener } from "../test/localListener.js";
import { startTrustAnchor } from "../test/trustAnchor.js";

import type { TrustAnchor } from "../test/trustAnchor.js";

/** A fixed instant, so the cache's age is the test's to choose. */
const START = new Date("2026-08-13T00:00:00Z");

/** `START` plus some seconds. */
function later(seconds: number): Date {
  return new Date(START.getTime() + seconds * 1000);
}

/** The `kid` values a resolution returned. */
function kidsOf(result: Awaited<ReturnType<typeof resolveRemoteJwks>>) {
  return result.ok ? result.keys.keys.map((key) => key.kid) : undefined;
}

/** Resolves against an anchor, with private addresses permitted. */
async function resolve(
  anchor: TrustAnchor,
  cache: ReturnType<typeof createRemoteJwksCache>,
  now: Date,
  kid?: string,
) {
  return await resolveRemoteJwks({
    jwksUri: anchor.jwksUri,
    cache,
    now,
    allowPrivateAddresses: true,
    ...(kid === undefined ? {} : { kid }),
  });
}

describe("resolveRemoteJwks", () => {
  it("fetches only through the outbound guard", async () => {
    const anchor = await startTrustAnchor();
    try {
      // The anchor is on loopback, which the guard refuses. A resolver calling
      // `fetch` directly would return the keys here, so this failing is the
      // property: the address is judged before anything is fetched.
      const result = await resolveRemoteJwks({
        jwksUri: anchor.jwksUri,
        cache: createRemoteJwksCache(),
        now: START,
      });

      expect(result.ok).toBe(false);
      expect(anchor.jwksFetches()).toBe(0);
    } finally {
      await anchor.close();
    }
  });

  it("returns the anchor's published keys", async () => {
    const anchor = await startTrustAnchor();
    try {
      const result = await resolve(anchor, createRemoteJwksCache(), START);

      expect(kidsOf(result)).toEqual([anchor.keyId]);
      expect(anchor.jwksFetches()).toBe(1);
    } finally {
      await anchor.close();
    }
  });

  it("serves a second resolution from the cache", async () => {
    const anchor = await startTrustAnchor();
    try {
      const cache = createRemoteJwksCache();
      await resolve(anchor, cache, START);
      const second = await resolve(anchor, cache, later(1), anchor.keyId);

      // Repeated registrations must not hammer the anchor.
      expect(kidsOf(second)).toEqual([anchor.keyId]);
      expect(anchor.jwksFetches()).toBe(1);
    } finally {
      await anchor.close();
    }
  });

  it("keeps a cached set for no longer than the maximum age", async () => {
    const anchor = await startTrustAnchor();
    try {
      const cache = createRemoteJwksCache();
      await resolve(anchor, cache, START);

      // One second inside the window is a hit; the boundary itself is a miss,
      // which is what makes "at most 300 seconds" true rather than "about 300".
      await resolve(anchor, cache, later(REMOTE_JWKS_MAX_AGE_SECONDS - 1));
      expect(anchor.jwksFetches()).toBe(1);

      await resolve(anchor, cache, later(REMOTE_JWKS_MAX_AGE_SECONDS));
      expect(anchor.jwksFetches()).toBe(2);
    } finally {
      await anchor.close();
    }
  });

  it("caches per address, not across anchors", async () => {
    const first = await startTrustAnchor();
    const second = await startTrustAnchor();
    try {
      const cache = createRemoteJwksCache();
      await resolve(first, cache, START);
      const other = await resolve(second, cache, START);

      // A cache keyed on anything coarser would verify one anchor's statements
      // against another anchor's keys.
      expect(kidsOf(other)).toEqual([second.keyId]);
      expect(second.jwksFetches()).toBe(1);
    } finally {
      await first.close();
      await second.close();
    }
  });

  it("refetches within the window when the kid is unknown", async () => {
    const anchor = await startTrustAnchor();
    try {
      const cache = createRemoteJwksCache();
      await resolve(anchor, cache, START);

      // The anchor rotates. A cached set that stayed authoritative for its whole
      // window would refuse every statement signed by the new key for five
      // minutes, so an unknown kid forces the fetch.
      const rotated = await anchor.addKey();
      const result = await resolve(anchor, cache, later(1), rotated);

      expect(kidsOf(result)).toContain(rotated);
      expect(anchor.jwksFetches()).toBe(2);
    } finally {
      await anchor.close();
    }
  });

  it("refetches once, not repeatedly, for a kid that stays unknown", async () => {
    const anchor = await startTrustAnchor();
    try {
      const cache = createRemoteJwksCache();
      await resolve(anchor, cache, START);
      const unpublished = await anchor.addKey({ publish: false });

      await resolve(anchor, cache, later(1), unpublished);
      expect(anchor.jwksFetches()).toBe(2);

      // A statement signed with a key the anchor does not publish must not turn
      // into one outbound request per attempt - that is an amplifier pointed at
      // the anchor by anybody who can reach the registration endpoint.
      await resolve(anchor, cache, later(2), unpublished);
      await resolve(anchor, cache, later(3), unpublished);
      expect(anchor.jwksFetches()).toBe(2);
    } finally {
      await anchor.close();
    }
  });

  it("still answers a known kid after refetching for an unknown one", async () => {
    const anchor = await startTrustAnchor();
    try {
      const cache = createRemoteJwksCache();
      const published = anchor.keyId;
      await resolve(anchor, cache, START);
      const unpublished = await anchor.addKey({ publish: false });
      await resolve(anchor, cache, later(1), unpublished);

      const result = await resolve(anchor, cache, later(2), published);

      expect(kidsOf(result)).toContain(published);
      expect(anchor.jwksFetches()).toBe(2);
    } finally {
      await anchor.close();
    }
  });

  it("refuses when the anchor cannot be fetched", async () => {
    const anchor = await startTrustAnchor();
    try {
      anchor.failJwksWith(503);
      const result = await resolve(anchor, createRemoteJwksCache(), START);

      expect(result.ok).toBe(false);
      expect(result.ok ? undefined : result.reason).toBe("fetch-failed");
      expect(anchor.jwksFetches()).toBe(1);
    } finally {
      await anchor.close();
    }
  });

  it("refuses rather than falling back to a set past its window", async () => {
    const anchor = await startTrustAnchor();
    try {
      const cache = createRemoteJwksCache();
      await resolve(anchor, cache, START);
      anchor.failJwksWith(503);

      const result = await resolve(
        anchor,
        cache,
        later(REMOTE_JWKS_MAX_AGE_SECONDS),
      );

      // Never verify against a cache older than the window. A withdrawn key
      // would otherwise keep verifying for as long as the anchor stayed down.
      expect(result.ok).toBe(false);
    } finally {
      await anchor.close();
    }
  });

  it("refuses rather than answering a stale kid when the refetch fails", async () => {
    const anchor = await startTrustAnchor();
    try {
      const cache = createRemoteJwksCache();
      await resolve(anchor, cache, START);
      const rotated = await anchor.addKey();
      anchor.failJwksWith(503);

      const result = await resolve(anchor, cache, later(1), rotated);

      expect(result.ok).toBe(false);
    } finally {
      await anchor.close();
    }
  });

  it("refuses a document that is not a JWK Set", async () => {
    const listener = await startLocalListener(() =>
      Promise.resolve(jsonResponse({ not: "a key set" })),
    );
    try {
      const result = await resolveRemoteJwks({
        jwksUri: `${listener.origin}/jwks`,
        cache: createRemoteJwksCache(),
        now: START,
        allowPrivateAddresses: true,
      });

      expect(result.ok).toBe(false);
      expect(result.ok ? undefined : result.reason).toBe("not-a-key-set");
    } finally {
      await listener.close();
    }
  });

  it("caches nothing it refused", async () => {
    const anchor = await startTrustAnchor();
    try {
      const cache = createRemoteJwksCache();
      anchor.failJwksWith(503);
      await resolve(anchor, cache, START);

      anchor.failJwksWith(undefined);
      const result = await resolve(anchor, cache, later(1));

      // A refusal that poisoned the cache would keep an anchor refused for the
      // rest of the window after it came back.
      expect(kidsOf(result)).toEqual([anchor.keyId]);
      expect(anchor.jwksFetches()).toBe(2);
    } finally {
      await anchor.close();
    }
  });

  it("reports why it refused, without inventing keys", async () => {
    const result = await resolveRemoteJwks({
      jwksUri: "not a url at all",
      cache: createRemoteJwksCache(),
      now: START,
    });

    expect(result.ok).toBe(false);
    expect(result.ok ? "" : result.description).toContain("not a url at all");
  });
});
