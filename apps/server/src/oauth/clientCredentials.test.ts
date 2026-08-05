/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  credentialClientId,
  extractClientCredential,
  JWT_BEARER_ASSERTION_TYPE,
  methodMatchesClientType,
} from "./clientCredentials.js";

/** Builds an `Authorization: Basic` header the RFC 6749 §2.3.1 way. */
function basic(clientId: string, secret: string): string {
  const encoded = Buffer.from(
    `${encodeURIComponent(clientId)}:${encodeURIComponent(secret)}`,
    "utf8",
  ).toString("base64");
  return `Basic ${encoded}`;
}

describe("extractClientCredential", () => {
  it("reads a Basic credential", () => {
    const result = extractClientCredential(basic("app", "s3cret"), {});
    expect(result).toEqual({
      ok: true,
      credential: {
        method: "client_secret_basic",
        clientId: "app",
        clientSecret: "s3cret",
      },
    });
  });

  it("accepts a lower-case scheme name", () => {
    const header = basic("app", "s3cret").replace("Basic", "basic");
    expect(extractClientCredential(header, {}).ok).toBe(true);
  });

  it("form-decodes both halves, so a colon in the secret survives", () => {
    const result = extractClientCredential(basic("app", "a:b"), {});
    expect(result.ok && result.credential).toMatchObject({
      clientId: "app",
      clientSecret: "a:b",
    });
  });

  it("decodes a plus as a space", () => {
    const header = `Basic ${Buffer.from("app:a+b", "utf8").toString("base64")}`;
    const result = extractClientCredential(header, {});
    expect(result.ok && result.credential).toMatchObject({
      clientSecret: "a b",
    });
  });

  it("refuses a Basic header that is not base64", () => {
    expect(extractClientCredential("Basic !!!!", {})).toEqual({
      ok: false,
      refusal: {
        code: "invalid_client",
        description: "The Authorization header is not a valid Basic credential",
      },
    });
  });

  it("refuses a Basic header with no colon", () => {
    const header = `Basic ${Buffer.from("appsecret", "utf8").toString("base64")}`;
    expect(extractClientCredential(header, {}).ok).toBe(false);
  });

  it("refuses a Basic header with an empty client id", () => {
    const header = `Basic ${Buffer.from(":secret", "utf8").toString("base64")}`;
    expect(extractClientCredential(header, {}).ok).toBe(false);
  });

  it("refuses a Basic header with an invalid percent escape", () => {
    const header = `Basic ${Buffer.from("app:%zz", "utf8").toString("base64")}`;
    expect(extractClientCredential(header, {}).ok).toBe(false);
  });

  it("accepts a body client_id that agrees with the header", () => {
    expect(
      extractClientCredential(basic("app", "s"), { clientId: "app" }).ok,
    ).toBe(true);
  });

  it("refuses a body client_id that contradicts the header", () => {
    expect(
      extractClientCredential(basic("app", "s"), { clientId: "other" }),
    ).toEqual({
      ok: false,
      refusal: {
        code: "invalid_client",
        description:
          "client_id in the request body does not match the Authorization header",
      },
    });
  });

  it("reads a post credential", () => {
    expect(
      extractClientCredential(undefined, {
        clientId: "app",
        clientSecret: "s3cret",
      }),
    ).toEqual({
      ok: true,
      credential: {
        method: "client_secret_post",
        clientId: "app",
        clientSecret: "s3cret",
      },
    });
  });

  it("reads a public client with no credential", () => {
    expect(extractClientCredential(undefined, { clientId: "app" })).toEqual({
      ok: true,
      credential: { method: "none", clientId: "app" },
    });
  });

  it("treats a blank secret as no secret", () => {
    expect(
      extractClientCredential(undefined, { clientId: "app", clientSecret: "" }),
    ).toEqual({ ok: true, credential: { method: "none", clientId: "app" } });
  });

  it("reads a private_key_jwt assertion", () => {
    expect(
      extractClientCredential(undefined, {
        clientAssertion: "a.b.c",
        clientAssertionType: JWT_BEARER_ASSERTION_TYPE,
      }),
    ).toEqual({
      ok: true,
      credential: {
        method: "private_key_jwt",
        clientId: undefined,
        assertion: "a.b.c",
      },
    });
  });

  it("carries the body client_id alongside an assertion", () => {
    const result = extractClientCredential(undefined, {
      clientId: "app",
      clientAssertion: "a.b.c",
      clientAssertionType: JWT_BEARER_ASSERTION_TYPE,
    });
    expect(result.ok && result.credential).toMatchObject({ clientId: "app" });
  });

  it("refuses an assertion with the wrong assertion type", () => {
    const result = extractClientCredential(undefined, {
      clientAssertion: "a.b.c",
      clientAssertionType: "urn:example:other",
    });
    expect(result).toMatchObject({
      ok: false,
      refusal: { code: "invalid_request" },
    });
  });

  it("refuses an assertion with no assertion type", () => {
    expect(
      extractClientCredential(undefined, { clientAssertion: "a.b.c" }).ok,
    ).toBe(false);
  });

  it("refuses an assertion type with no assertion", () => {
    const result = extractClientCredential(undefined, {
      clientId: "app",
      clientAssertionType: JWT_BEARER_ASSERTION_TYPE,
    });
    expect(result).toMatchObject({
      ok: false,
      refusal: { code: "invalid_request" },
    });
  });

  it("refuses a request with no client_id at all", () => {
    expect(extractClientCredential(undefined, {})).toEqual({
      ok: false,
      refusal: {
        code: "invalid_request",
        description: "client_id is required",
      },
    });
  });

  it("refuses two credentials at once", () => {
    expect(
      extractClientCredential(basic("app", "s"), {
        clientId: "app",
        clientSecret: "s",
      }),
    ).toMatchObject({
      ok: false,
      refusal: { code: "invalid_request" },
    });
    expect(
      extractClientCredential(basic("app", "s"), {
        clientAssertion: "a.b.c",
        clientAssertionType: JWT_BEARER_ASSERTION_TYPE,
      }).ok,
    ).toBe(false);
    expect(
      extractClientCredential(undefined, {
        clientId: "app",
        clientSecret: "s",
        clientAssertion: "a.b.c",
        clientAssertionType: JWT_BEARER_ASSERTION_TYPE,
      }).ok,
    ).toBe(false);
  });

  it("ignores an Authorization header using another scheme", () => {
    expect(extractClientCredential("Bearer abc", { clientId: "app" })).toEqual({
      ok: true,
      credential: { method: "none", clientId: "app" },
    });
  });
});

describe("credentialClientId", () => {
  it("reads the id from each credential shape", () => {
    expect(credentialClientId({ method: "none", clientId: "app" })).toBe("app");
    expect(
      credentialClientId({
        method: "private_key_jwt",
        clientId: undefined,
        assertion: "a.b.c",
      }),
    ).toBeUndefined();
  });
});

describe("methodMatchesClientType", () => {
  it("permits exactly one method per client type", () => {
    expect(methodMatchesClientType("none", "public")).toBe(true);
    expect(methodMatchesClientType("client_secret_basic", "public")).toBe(
      false,
    );
    expect(methodMatchesClientType("private_key_jwt", "public")).toBe(false);

    expect(
      methodMatchesClientType("client_secret_basic", "confidential-symmetric"),
    ).toBe(true);
    expect(
      methodMatchesClientType("client_secret_post", "confidential-symmetric"),
    ).toBe(true);
    expect(methodMatchesClientType("none", "confidential-symmetric")).toBe(
      false,
    );

    expect(
      methodMatchesClientType("private_key_jwt", "confidential-asymmetric"),
    ).toBe(true);
    expect(
      methodMatchesClientType("client_secret_post", "confidential-asymmetric"),
    ).toBe(false);
  });
});
