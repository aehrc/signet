/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The one-line description under each app on the management page.
 *
 * A standing grant and token-only access are different facts, and the sentence has to
 * say which one the person is looking at: a grant was "allowed" and can be
 * "withdrawn", while token-only access simply exists until it is taken away.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { describeEntry } from "./accessWording.js";

const GRANTED = "2026-08-09T00:00:00Z";
const REVOKED = "2026-08-10T00:00:00Z";

describe("describeEntry", () => {
  it("says when a standing grant was allowed", () => {
    const description = describeEntry({
      standing: true,
      active: true,
      grantedAt: GRANTED,
      revokedAt: null,
    });
    expect(description).toStartWith("Allowed on ");
  });

  it("says when a standing grant was withdrawn", () => {
    const description = describeEntry({
      standing: true,
      active: false,
      grantedAt: GRANTED,
      revokedAt: REVOKED,
    });
    expect(description).toStartWith("Withdrawn on ");
  });

  // An expired grant was never withdrawn, and "withdrawn on never" would be nonsense.
  it("says a standing grant expired when it ended without being withdrawn", () => {
    const description = describeEntry({
      standing: true,
      active: false,
      grantedAt: GRANTED,
      revokedAt: null,
    });
    expect(description).toBe("Expired");
  });

  it("describes token-only access as current access", () => {
    const description = describeEntry({
      standing: false,
      active: true,
      grantedAt: GRANTED,
      revokedAt: null,
    });
    expect(description).toStartWith("Has access since ");
  });
});
