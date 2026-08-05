/**
 * Deriving the suite's serving connection from the owning one.
 *
 * A developer configures one variable, `SIGNET_TEST_DATABASE_URL`, which names
 * the identity that owns the schema. Everything else - the serving role, its
 * grants, and the URL the suites actually connect on - follows from it. The
 * following is the part worth testing: a derivation that quietly produced a URL
 * pointing at a different host, or at the owner after all, would leave the whole
 * suite bypassing the policies while appearing to run under them.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { SERVING_TEST_ROLE, servingRoleUrl } from "./servingRole.js";

describe("servingRoleUrl", () => {
  it("swaps the credential and keeps everything else", () => {
    const derived = new URL(
      servingRoleUrl("postgres://signet:signet@localhost:55432/signet"),
    );

    expect(derived.username).toBe(SERVING_TEST_ROLE);
    expect(derived.hostname).toBe("localhost");
    expect(derived.port).toBe("55432");
    expect(derived.pathname).toBe("/signet");
  });

  it("does not leave the owner's credential in the result", () => {
    // The whole point. A derivation that kept the owner's password would
    // connect as the owner, which Postgres exempts from the policies, and the
    // suite would pass while proving nothing.
    const derived = servingRoleUrl(
      "postgres://signet:owner-secret@localhost:55432/signet",
    );

    expect(derived).not.toContain("owner-secret");
    expect(derived).not.toContain("signet:owner");
  });

  it("keeps connection parameters", () => {
    // A CI database reached over TLS carries `?sslmode=require`, and dropping it
    // would make the derived URL fail to connect for a reason unrelated to what
    // the suite is testing.
    expect(
      servingRoleUrl(
        "postgres://signet:signet@db.example.org:5432/signet?sslmode=require",
      ),
    ).toContain("sslmode=require");
  });

  it("refuses a URL it cannot parse", () => {
    expect(() => servingRoleUrl("not a url")).toThrow(
      /SIGNET_TEST_DATABASE_URL/,
    );
  });
});
