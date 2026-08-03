import { describe, expect, it } from "vitest";

import {
  accessTokenState,
  classifyConsumptionRefusal,
  classifyLaunchHandleRefusal,
  classifyRefreshTokenRefusal,
  isClientUsable,
  isEndUserEnabled,
  isExpired,
  isLive,
  isPersonaSelectable,
  isRevoked,
  nextPolicyVersion,
  shouldRevokeFamily,
} from "./predicates.js";

const NOW = new Date("2026-01-01T12:00:00.000Z");
const EARLIER = new Date("2026-01-01T11:59:59.000Z");
const LATER = new Date("2026-01-01T12:00:01.000Z");

describe("isExpired", () => {
  it("treats a lifetime that has run out as expired", () => {
    expect(isExpired(EARLIER, NOW)).toBe(true);
  });

  it("treats a lifetime still to come as live", () => {
    expect(isExpired(LATER, NOW)).toBe(false);
  });

  it("treats an expiry falling exactly on now as expired", () => {
    expect(isExpired(NOW, NOW)).toBe(true);
  });

  it("treats a null expiry as never expiring", () => {
    expect(isExpired(null, NOW)).toBe(false);
  });
});

describe("isRevoked and isLive", () => {
  it("reports an unrevoked, unexpired row as live", () => {
    expect(isLive({ revokedAt: null, expiresAt: LATER }, NOW)).toBe(true);
  });

  it("reports a revoked row as not live even before it expires", () => {
    const row = { revokedAt: EARLIER, expiresAt: LATER };
    expect(isRevoked(row)).toBe(true);
    expect(isLive(row, NOW)).toBe(false);
  });

  it("reports an expired row as not live even when unrevoked", () => {
    expect(isLive({ revokedAt: null, expiresAt: EARLIER }, NOW)).toBe(false);
  });
});

describe("accessTokenState", () => {
  it("reports an active token", () => {
    expect(accessTokenState({ revokedAt: null, expiresAt: LATER }, NOW)).toBe(
      "active",
    );
  });

  it("reports revocation ahead of expiry", () => {
    expect(
      accessTokenState({ revokedAt: EARLIER, expiresAt: EARLIER }, NOW),
    ).toBe("revoked");
  });

  it("reports expiry when the token was never revoked", () => {
    expect(accessTokenState({ revokedAt: null, expiresAt: EARLIER }, NOW)).toBe(
      "expired",
    );
  });
});

describe("classifyConsumptionRefusal", () => {
  it("reports a missing row as not found", () => {
    expect(classifyConsumptionRefusal(undefined, NOW)).toBe("not-found");
  });

  it("reports a consumed row as already consumed", () => {
    expect(
      classifyConsumptionRefusal(
        { consumedAt: EARLIER, expiresAt: LATER },
        NOW,
      ),
    ).toBe("already-consumed");
  });

  it("reports consumption ahead of expiry for a replayed, expired row", () => {
    expect(
      classifyConsumptionRefusal(
        { consumedAt: EARLIER, expiresAt: EARLIER },
        NOW,
      ),
    ).toBe("already-consumed");
  });

  it("reports an unconsumed, expired row as expired", () => {
    expect(
      classifyConsumptionRefusal({ consumedAt: null, expiresAt: EARLIER }, NOW),
    ).toBe("expired");
  });

  it("reports a live unconsumed row as not found, since the claim declined", () => {
    // Reaching here means the conditional UPDATE matched nothing even though the
    // row looks claimable, which can only be a concurrent claim that has since
    // been rolled back. There is nothing to report but absence.
    expect(
      classifyConsumptionRefusal({ consumedAt: null, expiresAt: LATER }, NOW),
    ).toBe("not-found");
  });
});

describe("classifyLaunchHandleRefusal", () => {
  const handle = { consumedAt: null, expiresAt: LATER, clientId: "client-a" };

  it("reports a mismatched client", () => {
    expect(classifyLaunchHandleRefusal(handle, "client-b", NOW)).toBe(
      "client-mismatch",
    );
  });

  it("reports the mismatch ahead of consumption", () => {
    expect(
      classifyLaunchHandleRefusal(
        { ...handle, consumedAt: EARLIER },
        "client-b",
        NOW,
      ),
    ).toBe("client-mismatch");
  });

  it("does not report a mismatch for an unbound handle", () => {
    expect(
      classifyLaunchHandleRefusal(
        { ...handle, clientId: null, consumedAt: EARLIER },
        "client-b",
        NOW,
      ),
    ).toBe("already-consumed");
  });

  it("does not report a mismatch for the client it was bound to", () => {
    expect(
      classifyLaunchHandleRefusal(
        { ...handle, consumedAt: EARLIER },
        "client-a",
        NOW,
      ),
    ).toBe("already-consumed");
  });

  it("reports a missing handle as not found", () => {
    expect(classifyLaunchHandleRefusal(undefined, "client-a", NOW)).toBe(
      "not-found",
    );
  });
});

describe("classifyRefreshTokenRefusal", () => {
  it("reports a missing token as not found", () => {
    expect(classifyRefreshTokenRefusal(undefined, NOW)).toBe("not-found");
  });

  it("reports a token with a successor as reused", () => {
    expect(
      classifyRefreshTokenRefusal(
        { revokedAt: EARLIER, expiresAt: LATER, replacedById: "successor" },
        NOW,
      ),
    ).toBe("reused");
  });

  it("reports reuse ahead of expiry, so theft after expiry is still theft", () => {
    expect(
      classifyRefreshTokenRefusal(
        { revokedAt: EARLIER, expiresAt: EARLIER, replacedById: "successor" },
        NOW,
      ),
    ).toBe("reused");
  });

  it("reports a revoked token with no successor as merely revoked", () => {
    expect(
      classifyRefreshTokenRefusal(
        { revokedAt: EARLIER, expiresAt: LATER, replacedById: null },
        NOW,
      ),
    ).toBe("revoked");
  });

  it("reports an unrevoked, expired token as expired", () => {
    expect(
      classifyRefreshTokenRefusal(
        { revokedAt: null, expiresAt: EARLIER, replacedById: null },
        NOW,
      ),
    ).toBe("expired");
  });
});

describe("shouldRevokeFamily", () => {
  it("revokes the family only for reuse", () => {
    expect(shouldRevokeFamily("reused")).toBe(true);
    expect(shouldRevokeFamily("revoked")).toBe(false);
    expect(shouldRevokeFamily("expired")).toBe(false);
    expect(shouldRevokeFamily("not-found")).toBe(false);
  });
});

describe("nextPolicyVersion", () => {
  it("starts at one", () => {
    expect(nextPolicyVersion(null)).toBe(1);
  });

  it("continues from the highest existing version", () => {
    expect(nextPolicyVersion(7)).toBe(8);
  });
});

describe("isPersonaSelectable", () => {
  const persona = { isPersona: true, disabledAt: null };

  it("permits a persona on a non-production endpoint", () => {
    expect(isPersonaSelectable({ isProduction: false }, persona)).toBe(true);
  });

  it("refuses every persona on a production endpoint", () => {
    expect(isPersonaSelectable({ isProduction: true }, persona)).toBe(false);
  });

  it("refuses a user who is not a persona", () => {
    expect(
      isPersonaSelectable(
        { isProduction: false },
        { ...persona, isPersona: false },
      ),
    ).toBe(false);
  });

  it("refuses a disabled persona", () => {
    expect(
      isPersonaSelectable(
        { isProduction: false },
        { ...persona, disabledAt: EARLIER },
      ),
    ).toBe(false);
  });
});

describe("isEndUserEnabled", () => {
  it("distinguishes a disabled account", () => {
    expect(isEndUserEnabled({ disabledAt: null })).toBe(true);
    expect(isEndUserEnabled({ disabledAt: EARLIER })).toBe(false);
  });
});

describe("isClientUsable", () => {
  it("permits only an active client", () => {
    expect(isClientUsable({ status: "active" })).toBe(true);
    for (const status of ["pending", "suspended", "rejected"]) {
      expect(isClientUsable({ status })).toBe(false);
    }
  });
});
