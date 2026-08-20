/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The pure half of a vouched registration.
 *
 * Everything here is a judgement over data the route has already fetched: the
 * request body, the statement's claims once its signature has verified, and the
 * metadata the anchor put inside it. No key is checked here and nothing is
 * written - which is exactly why these are the cases worth enumerating, because
 * each one is a refusal the endpoint has to be able to give distinctly.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  describeVouching,
  extractVouchedClientMetadata,
  parseRegistrationBody,
  PERMITTED_STATEMENT_ALGORITHMS,
  validateSoftwareStatement,
} from "./validate.js";

/** The instant every temporal case is judged against. */
const NOW = new Date("2026-08-13T00:00:00Z");

/** Seconds since the epoch, as a statement claim carries them. */
function epoch(date: Date): number {
  return Math.floor(date.getTime() / 1000);
}

/** `NOW` shifted by some seconds. */
function shifted(seconds: number): Date {
  return new Date(NOW.getTime() + seconds * 1000);
}

/** A compact JWS shape. The parts are never decoded by these functions. */
const COMPACT_JWS = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhIn0.c2lnbmF0dXJl";

/** The anchor every statement case is judged against. */
const ANCHOR = "https://anchor.example.org";

/** Statement claims with everything valid, before the case's overrides. */
function statementClaims(
  overrides: Readonly<Record<string, unknown>> = {},
): Record<string, unknown> {
  return {
    iss: ANCHOR,
    iat: epoch(NOW),
    exp: epoch(shifted(3600)),
    jti: "statement-1",
    ...overrides,
  };
}

/** Validates statement claims against the anchor, at `NOW`. */
function validate(
  overrides: Readonly<Record<string, unknown>> = {},
  maxVouchingDays = 30,
) {
  return validateSoftwareStatement({
    claims: statementClaims(overrides),
    anchorIssuer: ANCHOR,
    maxVouchingDays,
    now: NOW,
  });
}

/** The refusal code a validation produced, or undefined when it succeeded. */
function refusalOf(result: { readonly ok: boolean } & Record<string, unknown>) {
  return result.ok ? undefined : result["code"];
}

/** Metadata claims describing a workable public client. */
function metadataClaims(
  overrides: Readonly<Record<string, unknown>> = {},
): Record<string, unknown> {
  return {
    client_name: "Vouched test app",
    redirect_uris: ["https://app.example.org/callback"],
    grant_types: ["authorization_code", "refresh_token"],
    token_endpoint_auth_method: "none",
    scope: "launch/patient openid patient/*.rs",
    ...overrides,
  };
}

describe("parseRegistrationBody", () => {
  it("accepts a body carrying only a software statement", () => {
    const parsed = parseRegistrationBody({ software_statement: COMPACT_JWS });
    expect(parsed.ok).toBe(true);
    expect(parsed.ok ? parsed.softwareStatement : undefined).toBe(COMPACT_JWS);
  });

  it("refuses a body that is not an object", () => {
    // A bare string or an array is not a registration request; answering
    // "missing statement" for it would be misleading.
    expect(refusalOf(parseRegistrationBody("statement"))).toBe("not-an-object");
    expect(refusalOf(parseRegistrationBody(null))).toBe("not-an-object");
    expect(refusalOf(parseRegistrationBody([COMPACT_JWS]))).toBe(
      "not-an-object",
    );
  });

  it("refuses a body with no software statement", () => {
    expect(refusalOf(parseRegistrationBody({}))).toBe("missing-statement");
  });

  it("refuses a statement that is not a compact JWS", () => {
    // Shape only. Whether the signature verifies is a question for the anchor's
    // keys, and a two-part token never gets that far.
    expect(
      refusalOf(parseRegistrationBody({ software_statement: "abc" })),
    ).toBe("malformed-statement");
    expect(
      refusalOf(parseRegistrationBody({ software_statement: "a.b" })),
    ).toBe("malformed-statement");
    expect(refusalOf(parseRegistrationBody({ software_statement: 42 }))).toBe(
      "missing-statement",
    );
  });

  it("refuses metadata asserted alongside the statement rather than merging it", () => {
    // The whole point of the anchor is that the metadata is the anchor's. A
    // request that could add a redirect URI beside the statement would be a
    // request that registers a client the anchor never vouched for.
    const parsed = parseRegistrationBody({
      software_statement: COMPACT_JWS,
      redirect_uris: ["https://attacker.example.org/cb"],
    });
    expect(refusalOf(parsed)).toBe("metadata-outside-statement");
  });
});

describe("validateSoftwareStatement", () => {
  it("accepts a statement from the anchor within its validity", () => {
    const result = validate();
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.statement.issuer).toBe(ANCHOR);
      expect(result.statement.statementId).toBe("statement-1");
      expect(result.statement.expiresAt).toEqual(shifted(3600));
      expect(result.statement.issuedAt).toEqual(NOW);
    }
  });

  it("refuses claims that are not an object", () => {
    expect(
      refusalOf(
        validateSoftwareStatement({
          claims: "not-claims",
          anchorIssuer: ANCHOR,
          maxVouchingDays: 30,
          now: NOW,
        }),
      ),
    ).toBe("not-an-object");
  });

  it("refuses a statement from another issuer", () => {
    // The anchor is named by the rule, not by the statement: an issuer that does
    // not match is refused rather than trusted on its own say-so.
    expect(refusalOf(validate({ iss: "https://elsewhere.example.org" }))).toBe(
      "issuer-mismatch",
    );
    expect(refusalOf(validate({ iss: undefined }))).toBe("issuer-mismatch");
  });

  it("refuses a statement with no identifier, since it could not be spent", () => {
    expect(refusalOf(validate({ jti: undefined }))).toBe(
      "missing-statement-id",
    );
    expect(refusalOf(validate({ jti: "" }))).toBe("missing-statement-id");
  });

  it("refuses a statement with no expiry, which would vouch forever", () => {
    expect(refusalOf(validate({ exp: undefined }))).toBe("missing-expiry");
    expect(refusalOf(validate({ exp: "soon" }))).toBe("missing-expiry");
  });

  it("refuses a statement with no issuance time", () => {
    expect(refusalOf(validate({ iat: undefined }))).toBe("missing-issued-at");
  });

  it("refuses an expired statement", () => {
    expect(refusalOf(validate({ exp: epoch(shifted(-1)) }))).toBe("expired");
  });

  it("refuses a statement issued in the future beyond the clock tolerance", () => {
    // A minute of skew is tolerated, because two correct clocks disagree by
    // seconds; an hour is not a clock, it is a statement minted for later.
    expect(refusalOf(validate({ iat: epoch(shifted(30)) }))).toBeUndefined();
    expect(refusalOf(validate({ iat: epoch(shifted(3600)) }))).toBe(
      "issued-in-the-future",
    );
  });

  it("refuses a statement vouching for longer than the endpoint permits", () => {
    // The endpoint's ceiling wins, and it wins by refusing rather than by
    // silently shortening: a registration capped without the anchor's knowledge
    // is no longer the registration the anchor vouched for.
    const twoDays = epoch(shifted(2 * 86_400 + 60));
    expect(refusalOf(validate({ exp: twoDays }, 1))).toBe("vouching-too-long");
    expect(refusalOf(validate({ exp: twoDays }, 30))).toBeUndefined();
  });

  it("accepts a statement expiring exactly at the endpoint's ceiling", () => {
    // The boundary is inclusive: a statement written to the endpoint's stated
    // maximum is the statement an anchor configured to it will mint.
    expect(
      refusalOf(validate({ exp: epoch(shifted(86_400)) }, 1)),
    ).toBeUndefined();
  });

  it("names ES256 among the algorithms a statement may be signed with", () => {
    // The connectathon anchor signs with ES256; a permitted set that excluded it
    // would refuse every statement it ever mints.
    expect(PERMITTED_STATEMENT_ALGORITHMS).toContain("ES256");
    // Closed rather than open: `none` and the symmetric algorithms must never
    // appear, since a statement is verified against a published public key.
    expect(PERMITTED_STATEMENT_ALGORITHMS).not.toContain("none");
    expect(PERMITTED_STATEMENT_ALGORITHMS).not.toContain("HS256");
  });
});

describe("extractVouchedClientMetadata", () => {
  it("takes the client from the statement's metadata exactly", () => {
    const result = extractVouchedClientMetadata(metadataClaims());
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.metadata).toEqual({
        name: "Vouched test app",
        clientType: "public",
        redirectUris: ["https://app.example.org/callback"],
        grantTypes: ["authorization_code", "refresh_token"],
        scopes: ["launch/patient", "openid", "patient/*.rs"],
      });
    }
  });

  it("refuses metadata that is not an object", () => {
    expect(refusalOf(extractVouchedClientMetadata(null))).toBe("not-an-object");
  });

  it("refuses metadata with no client name", () => {
    expect(
      refusalOf(
        extractVouchedClientMetadata(
          metadataClaims({ client_name: undefined }),
        ),
      ),
    ).toBe("missing-name");
  });

  it("refuses an authorization-code client with no redirect URI", () => {
    expect(
      refusalOf(
        extractVouchedClientMetadata(
          metadataClaims({ redirect_uris: undefined }),
        ),
      ),
    ).toBe("missing-redirect-uris");
    expect(
      refusalOf(
        extractVouchedClientMetadata(metadataClaims({ redirect_uris: [] })),
      ),
    ).toBe("missing-redirect-uris");
  });

  it("refuses a redirect URI that is not an absolute URL", () => {
    // The anchor vouches for the metadata's origin, not for its validity: a
    // statement whose redirect URI would never match at `/authorize` is refused
    // here rather than producing a client that cannot complete a launch.
    expect(
      refusalOf(
        extractVouchedClientMetadata(
          metadataClaims({ redirect_uris: ["/callback"] }),
        ),
      ),
    ).toBe("malformed-redirect-uri");
  });

  it("refuses more redirect URIs than a registration may carry", () => {
    const many = Array.from(
      { length: 21 },
      (_unused, index) => `https://app.example.org/cb/${String(index)}`,
    );
    expect(
      refusalOf(
        extractVouchedClientMetadata(metadataClaims({ redirect_uris: many })),
      ),
    ).toBe("too-many-redirect-uris");
  });

  it("accepts a backend service with no redirect URI at all", () => {
    // A `client_credentials` client never visits `/authorize`, so it has nothing
    // to redirect to and requiring one would refuse a legitimate registration.
    const result = extractVouchedClientMetadata(
      metadataClaims({
        grant_types: ["client_credentials"],
        redirect_uris: undefined,
        token_endpoint_auth_method: "private_key_jwt",
        jwks_uri: "https://app.example.org/jwks",
      }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.metadata.redirectUris).toEqual([]);
      expect(result.metadata.clientType).toBe("confidential-asymmetric");
      expect(result.metadata.jwksUri).toBe("https://app.example.org/jwks");
    }
  });

  it("refuses a grant type Signet does not issue", () => {
    expect(
      refusalOf(
        extractVouchedClientMetadata(
          metadataClaims({ grant_types: ["implicit"] }),
        ),
      ),
    ).toBe("unsupported-grant-type");
    expect(
      refusalOf(
        extractVouchedClientMetadata(metadataClaims({ grant_types: [] })),
      ),
    ).toBe("unsupported-grant-type");
    expect(
      refusalOf(
        extractVouchedClientMetadata(
          metadataClaims({ grant_types: undefined }),
        ),
      ),
    ).toBe("unsupported-grant-type");
  });

  it("maps each authentication method onto the client type that presents it", () => {
    const typeFor = (method: string) => {
      const result = extractVouchedClientMetadata(
        metadataClaims({
          token_endpoint_auth_method: method,
          ...(method === "private_key_jwt"
            ? { jwks: { keys: [{ kty: "EC" }] } }
            : {}),
        }),
      );
      return result.ok ? result.metadata.clientType : refusalOf(result);
    };

    expect(typeFor("none")).toBe("public");
    expect(typeFor("client_secret_basic")).toBe("confidential-symmetric");
    expect(typeFor("client_secret_post")).toBe("confidential-symmetric");
    expect(typeFor("private_key_jwt")).toBe("confidential-asymmetric");
  });

  it("refuses an authentication method Signet does not accept", () => {
    // Including an absent one. RFC 7591 defaults it to `client_secret_basic`,
    // but inferring a credential posture from silence is exactly the inference
    // deny-by-default forbids.
    expect(
      refusalOf(
        extractVouchedClientMetadata(
          metadataClaims({ token_endpoint_auth_method: "client_secret_jwt" }),
        ),
      ),
    ).toBe("unsupported-auth-method");
    expect(
      refusalOf(
        extractVouchedClientMetadata(
          metadataClaims({ token_endpoint_auth_method: undefined }),
        ),
      ),
    ).toBe("unsupported-auth-method");
  });

  it("refuses an asymmetric client with nothing to verify its assertions against", () => {
    expect(
      refusalOf(
        extractVouchedClientMetadata(
          metadataClaims({ token_endpoint_auth_method: "private_key_jwt" }),
        ),
      ),
    ).toBe("missing-keys");
  });

  it("refuses an asymmetric client offering two key sources", () => {
    // With two there is no answer to "which key verified this assertion?".
    expect(
      refusalOf(
        extractVouchedClientMetadata(
          metadataClaims({
            token_endpoint_auth_method: "private_key_jwt",
            jwks: { keys: [{ kty: "EC" }] },
            jwks_uri: "https://app.example.org/jwks",
          }),
        ),
      ),
    ).toBe("conflicting-keys");
  });

  it("refuses keys offered by a client that authenticates without them", () => {
    // Stored silently they would vanish, and the anchor would believe it had
    // vouched for a client that verifies assertions when it does not.
    expect(
      refusalOf(
        extractVouchedClientMetadata(
          metadataClaims({ jwks_uri: "https://app.example.org/jwks" }),
        ),
      ),
    ).toBe("unexpected-keys");
  });

  it("carries the optional presentation fields when the statement has them", () => {
    const result = extractVouchedClientMetadata(
      metadataClaims({
        logo_uri: "https://app.example.org/logo.png",
        contacts: ["dev@example.org"],
      }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.metadata.logoUri).toBe("https://app.example.org/logo.png");
      expect(result.metadata.contactEmail).toBe("dev@example.org");
    }
  });

  it("treats an absent scope as granting nothing rather than everything", () => {
    const result = extractVouchedClientMetadata(
      metadataClaims({ scope: undefined }),
    );
    expect(result.ok).toBe(true);
    expect(result.ok ? result.metadata.scopes : undefined).toEqual([]);
  });
});

describe("describeVouching", () => {
  it("reports a client with no expiry as not vouched", () => {
    // Every client an administrator created is this case, and none of them may
    // be shown a vouching card or refused a token for one.
    const state = describeVouching(null, NOW);
    expect(state.vouched).toBe(false);
    expect(state.expired).toBe(false);
  });

  it("reports the time a live vouching has left", () => {
    const state = describeVouching(shifted(3 * 86_400), NOW);
    expect(state.vouched).toBe(true);
    expect(state.expired).toBe(false);
    expect(state.daysRemaining).toBe(3);
    expect(state.secondsRemaining).toBe(3 * 86_400);
  });

  it("rounds a part day down, so nothing reads as longer than it is", () => {
    expect(describeVouching(shifted(86_400 + 3600), NOW).daysRemaining).toBe(1);
    expect(describeVouching(shifted(3600), NOW).daysRemaining).toBe(0);
  });

  it("reports an expiry that has passed as expired, with nothing remaining", () => {
    const state = describeVouching(shifted(-1), NOW);
    expect(state.vouched).toBe(true);
    expect(state.expired).toBe(true);
    expect(state.secondsRemaining).toBe(0);
    expect(state.daysRemaining).toBe(0);
  });

  it("treats the instant of expiry itself as expired", () => {
    // The boundary matters: SC-005 measures a request that succeeded before it
    // failing after it, and "at" must fall on the refusing side.
    expect(describeVouching(NOW, NOW).expired).toBe(true);
  });
});
