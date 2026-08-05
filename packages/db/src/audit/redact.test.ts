/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  CYCLE_MARKER,
  isSensitiveKey,
  REDACTED_MARKER,
  redactAuditDetail,
  redactAuditText,
  TRUNCATED_MARKER,
  UNSUPPORTED_MARKER,
} from "./redact.js";

/** Builds an object nested `depth` levels deep with a leaf at the bottom. */
function nest(depth: number, leaf: unknown): unknown {
  let value: unknown = leaf;
  for (let level = 0; level < depth; level += 1) {
    value = { child: value };
  }
  return value;
}

describe("redactAuditDetail", () => {
  it("always produces an object, because the column is not null", () => {
    expect(redactAuditDetail(undefined)).toEqual({});
    expect(redactAuditDetail(null)).toEqual({});
    expect(redactAuditDetail("bare")).toEqual({ value: "bare" });
    expect(redactAuditDetail(42)).toEqual({ value: 42 });
    expect(redactAuditDetail([1, 2])).toEqual({ value: [1, 2] });
  });

  it("keeps values that are not credentials", () => {
    expect(
      redactAuditDetail({
        clientId: "app-1",
        grantType: "authorization_code",
        scopes: ["patient/Observation.rs"],
        granted: true,
        attempts: 3,
      }),
    ).toEqual({
      clientId: "app-1",
      grantType: "authorization_code",
      scopes: ["patient/Observation.rs"],
      granted: true,
      attempts: 3,
    });
  });

  it("replaces rather than drops, so the shape of what happened survives", () => {
    const redacted = redactAuditDetail({ password: "hunter2" });

    expect(redacted).toHaveProperty("password", REDACTED_MARKER);
    expect(Object.keys(redacted)).toEqual(["password"]);
  });

  it.each([
    "password",
    "Password",
    "PASSWORD",
    "new_password",
    "newPassword",
    "passphrase",
    "client_secret",
    "clientSecret",
    "Client-Secret",
    "CLIENTSECRET",
    "client secret",
    "secretHash",
    "refresh_token",
    "refreshToken",
    "access_token",
    "id_token",
    "authorization",
    "Authorization",
    "authorisation",
    "cookie",
    "Set-Cookie",
    "client_assertion",
    "assertion",
    "code_verifier",
    "codeVerifier",
    "private_jwk",
    "privateKey",
    "api_key",
    "credentials",
    "session_id",
    "recovery_codes",
    "code",
    "jwk",
    "key",
    "otp",
    "totp",
  ])("redacts the key %s", (key) => {
    expect(isSensitiveKey(key)).toBe(true);
    expect(redactAuditDetail({ [key]: "value" })).toEqual({
      [key]: REDACTED_MARKER,
    });
  });

  it.each([
    "clientId",
    "client_id",
    "status_code",
    "statusCode",
    "code_challenge_method",
    "codeChallenge",
    "jwks_uri",
    "jwks",
    "kid",
    "keyId",
    "scope",
    "redirect_uri",
    "fhirUser",
    "reason",
  ])("keeps the key %s", (key) => {
    expect(isSensitiveKey(key)).toBe(false);
    expect(redactAuditDetail({ [key]: "value" })).toEqual({ [key]: "value" });
  });

  it("redacts a sensitive key's whole subtree without descending into it", () => {
    expect(
      redactAuditDetail({
        credentials: { clientId: "app-1", note: "safe-looking" },
      }),
    ).toEqual({ credentials: REDACTED_MARKER });
  });

  it("redacts nested and array-nested occurrences", () => {
    expect(
      redactAuditDetail({
        request: {
          client: { clientId: "app-1", client_secret: "s3cr3t" },
          attempts: [
            { at: "2026-01-01", password: "a" },
            { at: "2026-01-02", password: "b" },
          ],
        },
      }),
    ).toEqual({
      request: {
        client: { clientId: "app-1", client_secret: REDACTED_MARKER },
        attempts: [
          { at: "2026-01-01", password: REDACTED_MARKER },
          { at: "2026-01-02", password: REDACTED_MARKER },
        ],
      },
    });
  });

  it("redacts credential-shaped values under innocuous keys", () => {
    const jwt = "eyJhbGciOiJSUzM4NCJ9.eyJzdWIiOiJhcHAtMSJ9.c2lnbmF0dXJlLWhlcmU";

    expect(
      redactAuditDetail({
        supplied: jwt,
        header: "Bearer abc.def.ghi",
        basic: "Basic YWJjOmRlZg==",
        pem: "-----BEGIN EC PRIVATE KEY-----\nMHcC\n-----END EC PRIVATE KEY-----",
      }),
    ).toEqual({
      supplied: REDACTED_MARKER,
      header: REDACTED_MARKER,
      basic: REDACTED_MARKER,
      pem: REDACTED_MARKER,
    });
  });

  it("does not mistake ordinary text for a credential", () => {
    expect(
      redactAuditDetail({
        note: "eye of the beholder",
        scope: "patient/*.rs launch/patient",
      }),
    ).toEqual({
      note: "eye of the beholder",
      scope: "patient/*.rs launch/patient",
    });
  });

  it("marks a self-referential object instead of overflowing", () => {
    const detail: Record<string, unknown> = { clientId: "app-1" };
    detail.self = detail;

    expect(redactAuditDetail(detail)).toEqual({
      clientId: "app-1",
      self: CYCLE_MARKER,
    });
  });

  it("marks a mutual cycle", () => {
    const left: Record<string, unknown> = { name: "left" };
    const right: Record<string, unknown> = { name: "right", left };
    left.right = right;

    expect(redactAuditDetail(left)).toEqual({
      name: "left",
      right: { name: "right", left: CYCLE_MARKER },
    });
  });

  it("marks a cycle through an array", () => {
    const items: unknown[] = [];
    const root = { items };
    items.push(root);

    expect(redactAuditDetail(root)).toEqual({ items: [CYCLE_MARKER] });
  });

  it("keeps a repeated sibling, which is sharing rather than a cycle", () => {
    const shared = { kind: "endpoint" };

    expect(redactAuditDetail({ before: shared, after: shared })).toEqual({
      before: { kind: "endpoint" },
      after: { kind: "endpoint" },
    });
  });

  it("produces output that JSON can serialise even from a cyclic input", () => {
    const detail: Record<string, unknown> = {};
    detail.loop = detail;

    expect(() => JSON.stringify(redactAuditDetail(detail))).not.toThrow();
  });

  it("truncates containers below the depth cap but keeps leaf primitives", () => {
    const shallow = redactAuditDetail(nest(5, { leaf: "kept" }));
    expect(JSON.stringify(shallow)).toContain("kept");

    const deep = redactAuditDetail(nest(9, { leaf: "buried" }));
    const serialised = JSON.stringify(deep);
    expect(serialised).not.toContain("buried");
    expect(serialised).toContain(TRUNCATED_MARKER);
  });

  it("caps array length and says so", () => {
    const values = Array.from({ length: 200 }, (_, index) => index);
    const result = redactAuditDetail({ values }) as { values: unknown[] };

    expect(result.values.length).toBeLessThan(values.length);
    expect(result.values.at(-1)).toBe(TRUNCATED_MARKER);
  });

  it("caps object width and records how many keys were dropped", () => {
    const wide = Object.fromEntries(
      Array.from({ length: 100 }, (_, index) => [`k${index}`, index]),
    );
    const result = redactAuditDetail(wide);

    expect(Object.keys(result).length).toBeLessThan(101);
    expect(result[TRUNCATED_MARKER]).toBeTypeOf("number");
  });

  it("caps a long string", () => {
    const result = redactAuditDetail({ note: "x".repeat(10_000) }) as {
      note: string;
    };

    expect(result.note.length).toBeLessThan(10_000);
    expect(result.note.endsWith(TRUNCATED_MARKER)).toBe(true);
  });

  it("bounds total work on a broad structure without throwing", () => {
    const wide = {
      rows: Array.from({ length: 64 }, () => ({
        a: 1,
        b: 2,
        c: 3,
        d: 4,
        e: 5,
        f: 6,
        g: 7,
        h: 8,
      })),
    };

    const serialised = JSON.stringify(redactAuditDetail(wide));
    expect(serialised).toContain(TRUNCATED_MARKER);
  });

  it("normalises values that JSON cannot hold", () => {
    expect(
      redactAuditDetail({
        when: new Date("2026-03-01T00:00:00.000Z"),
        invalidDate: new Date("not a date"),
        big: 10n,
        nan: Number.NaN,
        infinite: Number.POSITIVE_INFINITY,
        missing: undefined,
        fn: () => "no",
        sym: Symbol("no"),
      }),
    ).toEqual({
      when: "2026-03-01T00:00:00.000Z",
      invalidDate: null,
      big: "10",
      nan: null,
      infinite: null,
      missing: null,
      fn: UNSUPPORTED_MARKER,
      sym: UNSUPPORTED_MARKER,
    });
  });

  it("converts a Set and a Map rather than serialising them as empty", () => {
    expect(
      redactAuditDetail({
        scopes: new Set(["openid", "fhirUser"]),
        headers: new Map<string, string>([
          ["content-type", "application/json"],
          ["authorization", "Bearer abc"],
        ]),
      }),
    ).toEqual({
      scopes: ["openid", "fhirUser"],
      headers: {
        "content-type": "application/json",
        authorization: REDACTED_MARKER,
      },
    });
  });

  it("reduces an Error to its name and message, without the stack", () => {
    const result = redactAuditDetail({
      cause: new TypeError("bad audience"),
    }) as { cause: Record<string, unknown> };

    expect(result.cause).toEqual({
      name: "TypeError",
      message: "bad audience",
    });
  });

  it("redacts a credential quoted inside an error message", () => {
    const result = redactAuditDetail({
      cause: new Error("Bearer abcdefghij was rejected"),
    }) as { cause: Record<string, unknown> };

    expect(result.cause.message).toBe(REDACTED_MARKER);
  });
});

describe("redactAuditText", () => {
  it("passes ordinary text through", () => {
    expect(redactAuditText("Dr Alice Smith")).toBe("Dr Alice Smith");
  });

  it("redacts a credential-shaped value", () => {
    expect(redactAuditText("Basic YWJjOmRlZg==")).toBe(REDACTED_MARKER);
  });

  it("caps length", () => {
    expect(redactAuditText("y".repeat(5000)).length).toBeLessThan(5000);
  });
});
