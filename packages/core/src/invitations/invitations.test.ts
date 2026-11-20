/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Invitation links: who may be sent one, how long it lasts, and how the token travels.
 *
 * The console decides whether to offer an invitation and the server decides whether to
 * mint one, and the two must agree; so must the URL the server builds and the parser
 * the invitation page reads it back with.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  INVITATION_REFUSAL_MESSAGES,
  INVITATION_TTL_SECONDS,
  invitationExpiry,
  invitationRefusal,
  invitationTokenFromFragment,
  invitationUrl,
} from "./invitations.js";

const LOCAL = { authMode: "local" };
const FEDERATED = { authMode: "oidc" };
const PERSONA_MODE = { authMode: "persona" };
const ACCOUNT = { isPersona: false, disabledAt: null };

describe("invitationRefusal", () => {
  it("admits an enabled local account with access to an endpoint that checks passwords", () => {
    expect(invitationRefusal(ACCOUNT, [LOCAL])).toBeUndefined();
  });

  it("admits an account with one password endpoint among others", () => {
    // The password is checked at the local endpoint, which is reason enough.
    expect(
      invitationRefusal(ACCOUNT, [FEDERATED, LOCAL, PERSONA_MODE]),
    ).toBeUndefined();
  });

  it("refuses a persona, which has no password to choose", () => {
    expect(invitationRefusal({ ...ACCOUNT, isPersona: true }, [LOCAL])).toBe(
      "persona",
    );
  });

  it("refuses an account whose endpoints never check a local password", () => {
    expect(invitationRefusal(ACCOUNT, [FEDERATED, PERSONA_MODE])).toBe(
      "no-password-endpoint",
    );
  });

  it("refuses an account with access to no endpoint at all", () => {
    expect(invitationRefusal(ACCOUNT, [])).toBe("no-password-endpoint");
  });

  it("refuses a disabled account, which could not sign in with the password", () => {
    expect(
      invitationRefusal(
        { ...ACCOUNT, disabledAt: new Date("2026-01-01T00:00:00Z") },
        [LOCAL],
      ),
    ).toBe("disabled");
  });

  it("reads a disabled instant serialised as a string, as the console holds it", () => {
    expect(
      invitationRefusal(
        { ...ACCOUNT, disabledAt: "2026-01-01T00:00:00.000Z" },
        [LOCAL],
      ),
    ).toBe("disabled");
  });

  it("refuses an unrecognised auth mode rather than assuming local", () => {
    // Deny by default: a mode added later must be admitted by a rule naming it.
    expect(invitationRefusal(ACCOUNT, [{ authMode: "something-new" }])).toBe(
      "no-password-endpoint",
    );
  });

  it("names the persona before anything else, since it can never be fixed", () => {
    expect(
      invitationRefusal({ isPersona: true, disabledAt: new Date() }, []),
    ).toBe("persona");
  });

  it("explains every refusal", () => {
    for (const message of Object.values(INVITATION_REFUSAL_MESSAGES)) {
      expect(message.length).toBeGreaterThan(20);
    }
  });
});

describe("invitationExpiry", () => {
  it("is seven days after the moment of issue", () => {
    const now = new Date("2026-11-13T00:00:00Z");
    expect(invitationExpiry(now).toISOString()).toBe(
      "2026-11-20T00:00:00.000Z",
    );
    expect(INVITATION_TTL_SECONDS).toBe(7 * 24 * 60 * 60);
  });
});

describe("invitationUrl and invitationTokenFromFragment", () => {
  const tenantUrl = "https://signet.example.org/t/demo";

  it("puts the token in the fragment of the tenant's invitation page", () => {
    // The fragment is never sent to a server, so the token stays out of access logs,
    // proxies and the Referer header of anything the page loads.
    expect(invitationUrl(tenantUrl, "abc_DEF-123")).toBe(
      "https://signet.example.org/t/demo/invitation#abc_DEF-123",
    );
  });

  it("reads back exactly the token it wrote", () => {
    const url = new URL(invitationUrl(tenantUrl, "abc_DEF-123"));
    expect(invitationTokenFromFragment(url.hash)).toBe("abc_DEF-123");
  });

  it("finds no token in an empty fragment", () => {
    expect(invitationTokenFromFragment("")).toBeUndefined();
    expect(invitationTokenFromFragment("#")).toBeUndefined();
  });

  it("finds no token in a fragment outside the base64url alphabet", () => {
    // Anything else was not written by invitationUrl, and is refused here rather than
    // being sent to the server to be refused there.
    expect(invitationTokenFromFragment("#not a token")).toBeUndefined();
    expect(invitationTokenFromFragment("#a/b")).toBeUndefined();
  });
});
