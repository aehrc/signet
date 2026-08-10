/**
 * The management page's view of who can act: stored consents merged with live tokens.
 *
 * The property under test is the one the "always" consent mode broke: an app holding a
 * live token must appear on the management page even when no consent row was ever
 * stored, or the page shows "no apps have access" to a person whose record three apps
 * can read right now.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { buildAppAccess } from "./appAccess.js";

import type { ConsentGrant, IssuedToken, KnownClient } from "./appAccess.js";

const NOW = new Date("2026-08-10T00:00:00Z");
const EARLIER = new Date("2026-08-09T00:00:00Z");
const LATER = new Date("2026-08-11T00:00:00Z");

const APP: KnownClient = {
  rowId: "row-app",
  clientId: "app-client-id",
  name: "Growth Chart",
  logoUrl: null,
};

const OTHER: KnownClient = {
  rowId: "row-other",
  clientId: "other-client-id",
  name: "Other App",
  logoUrl: "https://other.test/logo.png",
};

/** A live access token for the given client, overridable per test. */
function liveToken(
  clientRowId: string,
  overrides: Partial<IssuedToken> = {},
): IssuedToken {
  return {
    clientRowId,
    scope: "openid patient/Observation.rs",
    issuedAt: EARLIER,
    expiresAt: LATER,
    revokedAt: null,
    ...overrides,
  };
}

/** A stored consent for the given client, overridable per test. */
function consent(
  client: KnownClient,
  overrides: Partial<ConsentGrant> = {},
): ConsentGrant {
  return {
    consentId: `consent-${client.rowId}`,
    clientId: client.clientId,
    clientName: client.name,
    logoUrl: client.logoUrl,
    scope: "openid patient/Observation.rs",
    grantedAt: EARLIER,
    expiresAt: null,
    revokedAt: null,
    ...overrides,
  };
}

describe("buildAppAccess", () => {
  it("returns nothing when there are no consents and no tokens", () => {
    const view = buildAppAccess({
      consents: [],
      accessTokens: [],
      refreshTokens: [],
      clients: [APP],
      now: NOW,
    });

    expect(view.entries).toEqual([]);
    expect(view.liveTokens).toEqual({ access: 0, refresh: 0 });
  });

  it("keeps a stored consent as a standing entry", () => {
    const view = buildAppAccess({
      consents: [consent(APP)],
      accessTokens: [],
      refreshTokens: [],
      clients: [APP],
      now: NOW,
    });

    expect(view.entries).toHaveLength(1);
    const entry = view.entries[0];
    expect(entry?.consentId).toBe("consent-row-app");
    expect(entry?.standing).toBe(true);
    expect(entry?.active).toBe(true);
    expect(entry?.scope).toEqual(["openid", "patient/Observation.rs"]);
  });

  it("marks a revoked consent inactive but keeps it on the list", () => {
    const view = buildAppAccess({
      consents: [consent(APP, { revokedAt: EARLIER })],
      accessTokens: [],
      refreshTokens: [],
      clients: [APP],
      now: NOW,
    });

    expect(view.entries[0]?.active).toBe(false);
    expect(view.entries[0]?.revokedAt).toEqual(EARLIER);
  });

  it("marks an expired consent inactive", () => {
    const view = buildAppAccess({
      consents: [consent(APP, { expiresAt: EARLIER })],
      accessTokens: [],
      refreshTokens: [],
      clients: [APP],
      now: NOW,
    });

    expect(view.entries[0]?.active).toBe(false);
  });

  // The heart of the fix: an "always"-mode endpoint stores no consent, so the only
  // record of the grant is the token it minted.
  it("lists an app that holds a live token but no consent", () => {
    const view = buildAppAccess({
      consents: [],
      accessTokens: [liveToken(APP.rowId)],
      refreshTokens: [],
      clients: [APP],
      now: NOW,
    });

    expect(view.entries).toHaveLength(1);
    const entry = view.entries[0];
    expect(entry?.consentId).toBeNull();
    expect(entry?.standing).toBe(false);
    expect(entry?.active).toBe(true);
    expect(entry?.clientId).toBe(APP.clientId);
    expect(entry?.clientName).toBe(APP.name);
    expect(entry?.scope).toEqual(["openid", "patient/Observation.rs"]);
    expect(entry?.grantedAt).toEqual(EARLIER);
    expect(entry?.expiresAt).toEqual(LATER);
  });

  it("ignores revoked and expired tokens entirely", () => {
    const view = buildAppAccess({
      consents: [],
      accessTokens: [
        liveToken(APP.rowId, { revokedAt: EARLIER }),
        liveToken(APP.rowId, { expiresAt: EARLIER }),
      ],
      refreshTokens: [liveToken(APP.rowId, { revokedAt: EARLIER })],
      clients: [APP],
      now: NOW,
    });

    expect(view.entries).toEqual([]);
    expect(view.liveTokens).toEqual({ access: 0, refresh: 0 });
  });

  it("counts only live tokens, not every row ever issued", () => {
    const view = buildAppAccess({
      consents: [],
      accessTokens: [
        liveToken(APP.rowId),
        liveToken(APP.rowId, { revokedAt: EARLIER }),
      ],
      refreshTokens: [liveToken(APP.rowId)],
      clients: [APP],
      now: NOW,
    });

    expect(view.liveTokens).toEqual({ access: 1, refresh: 1 });
  });

  it("does not add a token entry for a client with a live consent", () => {
    const view = buildAppAccess({
      consents: [consent(APP)],
      accessTokens: [liveToken(APP.rowId)],
      refreshTokens: [],
      clients: [APP],
      now: NOW,
    });

    // The consent entry already tells the person this app can act; a second row for
    // the same client would read as two separate grants.
    expect(view.entries).toHaveLength(1);
    expect(view.entries[0]?.standing).toBe(true);
  });

  // A revoked consent alongside a live token can happen when an endpoint's consent
  // mode changed, and both facts matter: the grant ended, yet the app can still act.
  it("adds a token entry even when the same client has a revoked consent", () => {
    const view = buildAppAccess({
      consents: [consent(APP, { revokedAt: EARLIER })],
      accessTokens: [liveToken(APP.rowId)],
      refreshTokens: [],
      clients: [APP],
      now: NOW,
    });

    expect(view.entries).toHaveLength(2);
    expect(view.entries[0]?.standing).toBe(true);
    expect(view.entries[0]?.active).toBe(false);
    expect(view.entries[1]?.standing).toBe(false);
    expect(view.entries[1]?.active).toBe(true);
  });

  it("merges a client's live tokens into one entry", () => {
    const view = buildAppAccess({
      consents: [],
      accessTokens: [
        liveToken(APP.rowId, { issuedAt: NOW, scope: "patient/Condition.rs" }),
        liveToken(APP.rowId, { issuedAt: EARLIER }),
      ],
      refreshTokens: [
        liveToken(APP.rowId, {
          expiresAt: new Date("2026-08-20T00:00:00Z"),
        }),
      ],
      clients: [APP],
      now: NOW,
    });

    expect(view.entries).toHaveLength(1);
    const entry = view.entries[0];
    // Access began with the earliest live token and ends with the last to expire.
    expect(entry?.grantedAt).toEqual(EARLIER);
    expect(entry?.expiresAt).toEqual(new Date("2026-08-20T00:00:00Z"));
    // The union of every live token's scopes, without duplicates.
    expect(entry?.scope).toEqual([
      "patient/Condition.rs",
      "openid",
      "patient/Observation.rs",
    ]);
  });

  it("keeps token entries for different clients separate", () => {
    const view = buildAppAccess({
      consents: [],
      accessTokens: [
        liveToken(APP.rowId, { issuedAt: NOW }),
        liveToken(OTHER.rowId, { issuedAt: EARLIER }),
      ],
      refreshTokens: [],
      clients: [APP, OTHER],
      now: NOW,
    });

    // Newest access first, mirroring the consent ordering.
    expect(view.entries.map((entry) => entry.clientId)).toEqual([
      APP.clientId,
      OTHER.clientId,
    ]);
    expect(view.entries[1]?.logoUrl).toBe("https://other.test/logo.png");
  });

  it("omits a token whose client is not on the endpoint's list", () => {
    const view = buildAppAccess({
      consents: [],
      accessTokens: [liveToken("row-unknown")],
      refreshTokens: [],
      clients: [APP],
      now: NOW,
    });

    // Nothing to name the entry with; the token still counts as live.
    expect(view.entries).toEqual([]);
    expect(view.liveTokens.access).toBe(1);
  });
});
