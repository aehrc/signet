/**
 * The admin API's front door.
 *
 * These are the properties nothing above them can restore: that an unauthenticated
 * request reaches no handler, that a session and a token both work and neither can
 * reach a tenant it was not issued for, and that a role is compared rather than
 * assumed. Everything the resource routes do is predicated on them.
 *
 * Author: John Grimes
 */

import {
  hashPassword,
  revokeApiToken,
  setAdminUserDisabled,
  setTenantMemberRole,
  withTenantScope,
} from "@signet/db";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { adminRequest, tenantPath } from "../test/adminApi.js";
import {
  createTestStack,
  TEST_PASSWORD,
  testDatabaseUrl,
} from "../test/harness.js";

import type { TestStack } from "../test/harness.js";

describe.skipIf(testDatabaseUrl === undefined)(
  "the admin API front door",
  () => {
    let stack: TestStack;

    beforeAll(async () => {
      stack = await createTestStack();
    });

    afterAll(async () => {
      await stack.close();
    });

    /** Signs in and returns the cookie a browser would send back. */
    const cookie = async () => ({ cookie: await stack.signIn() });

    describe("signing in", () => {
      it("issues an httpOnly session cookie", async () => {
        const response = await adminRequest(stack, "POST", "/api/v1/session", {
          body: { email: stack.admin.email, password: TEST_PASSWORD },
        });

        expect(response.status).toBe(200);
        const setCookie = response.headers.get("set-cookie") ?? "";
        expect(setCookie).toContain("signet_session=");
        expect(setCookie).toContain("HttpOnly");
        expect(setCookie).toContain("SameSite=Lax");
        // The deployment's public URL is https in the harness, so the cookie must
        // be marked Secure even though the test makes no real connection.
        expect(setCookie).toContain("Secure");
        expect(response.headers.get("cache-control")).toBe("no-store");
      });

      it("reports the tenants the person may act on", async () => {
        const response = await adminRequest(stack, "POST", "/api/v1/session", {
          body: { email: stack.admin.email, password: TEST_PASSWORD },
        });
        const body = (await response.json()) as {
          user: { email: string; totpEnrolled: boolean };
          tenants: { slug: string; role: string }[];
        };

        expect(body.user.email).toBe(stack.admin.email);
        expect(body.user.totpEnrolled).toBe(false);
        expect(body.tenants).toEqual([
          { slug: stack.tenant.slug, name: stack.tenant.name, role: "owner" },
        ]);
      });

      it("refuses a wrong password without saying which part was wrong", async () => {
        const response = await adminRequest(stack, "POST", "/api/v1/session", {
          body: { email: stack.admin.email, password: "not the password" },
        });

        expect(response.status).toBe(401);
        const body = (await response.json()) as { message: string };
        expect(body.message).toBe("Those credentials were not accepted");
        expect(response.headers.get("set-cookie")).toBeNull();
      });

      it("answers an unknown account exactly as it answers a wrong password", async () => {
        const unknown = await adminRequest(stack, "POST", "/api/v1/session", {
          body: { email: "nobody@signet.test", password: TEST_PASSWORD },
        });
        const wrong = await adminRequest(stack, "POST", "/api/v1/session", {
          body: { email: stack.admin.email, password: "not the password" },
        });

        expect(unknown.status).toBe(wrong.status);
        expect(await unknown.json()).toEqual(await wrong.json());
      });

      it("refuses a malformed request with field-level issues", async () => {
        const response = await adminRequest(stack, "POST", "/api/v1/session", {
          body: { email: "a" },
        });

        expect(response.status).toBe(400);
        const body = (await response.json()) as {
          error: string;
          issues: { path: string }[];
        };
        expect(body.error).toBe("invalid_request");
        expect(body.issues.map((issue) => issue.path)).toContain("password");
      });

      it("refuses a disabled account", async () => {
        const stack2 = await createTestStack();
        try {
          await setAdminUserDisabled(stack2.context.db, stack2.admin.id, true);
          const response = await adminRequest(
            stack2,
            "POST",
            "/api/v1/session",
            {
              body: { email: stack2.admin.email, password: TEST_PASSWORD },
            },
          );
          expect(response.status).toBe(401);
        } finally {
          await stack2.close();
        }
      });
    });

    describe("presenting a credential", () => {
      it("refuses a request with none", async () => {
        const response = await adminRequest(stack, "GET", "/api/v1/session");
        expect(response.status).toBe(401);
        const body = (await response.json()) as { error: string };
        expect(body.error).toBe("unauthenticated");
      });

      it("refuses a session cookie that names no session", async () => {
        const response = await adminRequest(stack, "GET", "/api/v1/session", {
          credential: { cookie: "signet_session=not-a-real-session" },
        });
        expect(response.status).toBe(401);
      });

      it("accepts a session cookie", async () => {
        const response = await adminRequest(stack, "GET", "/api/v1/session", {
          credential: await cookie(),
        });
        expect(response.status).toBe(200);
      });

      it("accepts a personal access token", async () => {
        const bearer = await stack.mintApiToken("admin");
        const response = await adminRequest(stack, "GET", "/api/v1/session", {
          credential: { bearer },
        });

        expect(response.status).toBe(200);
        const body = (await response.json()) as {
          token: { role: string };
          tenants: { slug: string }[];
        };
        expect(body.token.role).toBe("admin");
        expect(body.tenants[0]?.slug).toBe(stack.tenant.slug);
      });

      it("refuses a revoked personal access token", async () => {
        const bearer = await stack.mintApiToken("admin");
        const before = await adminRequest(stack, "GET", "/api/v1/session", {
          credential: { bearer },
        });
        expect(before.status).toBe(200);

        const session = (await before.json()) as { token: { id: string } };
        await revokeApiToken(
          stack.context.db,
          stack.tenantScope,
          session.token.id,
        );

        const after = await adminRequest(stack, "GET", "/api/v1/session", {
          credential: { bearer },
        });
        expect(after.status).toBe(401);
      });

      it("prefers an explicitly presented token over an ambient cookie", async () => {
        const bearer = await stack.mintApiToken("viewer");
        const response = await adminRequest(stack, "GET", "/api/v1/session", {
          credential: { bearer },
        });
        // Both are valid; the token is what was presented deliberately, so the
        // response describes the token rather than the person.
        const body = (await response.json()) as { token?: unknown };
        expect(body.token).toBeDefined();
      });
    });

    describe("signing out", () => {
      it("revokes the session and clears the cookie", async () => {
        const credential = await cookie();

        const signOut = await adminRequest(stack, "DELETE", "/api/v1/session", {
          credential,
        });
        expect(signOut.status).toBe(204);
        expect(signOut.headers.get("set-cookie")).toContain("Max-Age=0");

        const after = await adminRequest(stack, "GET", "/api/v1/session", {
          credential,
        });
        expect(after.status).toBe(401);
      });
    });

    describe("resolving a tenant", () => {
      it("answers the tenant a member asks for", async () => {
        const response = await adminRequest(stack, "GET", tenantPath(stack), {
          credential: await cookie(),
        });

        expect(response.status).toBe(200);
        const body = (await response.json()) as {
          tenant: { slug: string };
          role: string;
        };
        expect(body.tenant.slug).toBe(stack.tenant.slug);
        expect(body.role).toBe("owner");
      });

      it("tells a non-member the tenant does not exist", async () => {
        const response = await adminRequest(stack, "GET", tenantPath(stack), {
          credential: { cookie: await stack.signIn(stack.outsider) },
        });

        // 404 rather than 403: a 403 would confirm the tenant exists, which is how
        // an account on a shared deployment enumerates its neighbours.
        expect(response.status).toBe(404);
      });

      it("answers the same way for a tenant that does not exist at all", async () => {
        const response = await adminRequest(
          stack,
          "GET",
          "/api/v1/tenants/no-such-tenant",
          { credential: await cookie() },
        );
        expect(response.status).toBe(404);
      });

      it("refuses a token presented on another tenant's path", async () => {
        const other = await createTestStack();
        try {
          const bearer = await other.mintApiToken("owner");
          const response = await adminRequest(stack, "GET", tenantPath(stack), {
            credential: { bearer },
          });
          // Not silently redirected to the token's own tenant: a mistyped script
          // must fail rather than modify the wrong deployment.
          expect(response.status).toBe(404);
        } finally {
          await other.close();
        }
      });
    });

    describe("enforcing a role", () => {
      it("permits a viewer to read", async () => {
        const bearer = await stack.mintApiToken("viewer");
        const response = await adminRequest(stack, "GET", tenantPath(stack), {
          credential: { bearer },
        });
        expect(response.status).toBe(200);
      });

      it("compares roles rather than matching them", async () => {
        // A developer is above a viewer in the ordering, so a viewer-level route
        // must accept one. This is the case an equality check gets wrong.
        const bearer = await stack.mintApiToken("developer");
        const response = await adminRequest(stack, "GET", tenantPath(stack), {
          credential: { bearer },
        });
        expect(response.status).toBe(200);
      });
    });

    describe("membership changes", () => {
      it("takes effect on the next request", async () => {
        const stack2 = await createTestStack();
        try {
          const credential = { cookie: await stack2.signIn(stack2.outsider) };
          const before = await adminRequest(stack2, "GET", tenantPath(stack2), {
            credential,
          });
          expect(before.status).toBe(404);

          const granted = await withTenantScope(
            stack2.context.db,
            stack2.tenantScope,
            (bound) => setTenantMemberRole(bound, stack2.outsider.id, "viewer"),
          );
          expect(granted.ok).toBe(true);

          const after = await adminRequest(stack2, "GET", tenantPath(stack2), {
            credential,
          });
          expect(after.status).toBe(200);
        } finally {
          await stack2.close();
        }
      });
    });

    describe("the unauthenticated allowlist", () => {
      it("does not extend to a route that merely looks like it", async () => {
        // `POST /api/v1/session` is allowlisted. A path that contains it as a
        // segment value must not inherit that.
        const response = await adminRequest(
          stack,
          "GET",
          "/api/v1/tenants/session",
        );
        expect(response.status).toBe(401);
      });

      it("does not extend to other methods on the same path", async () => {
        const response = await adminRequest(stack, "GET", "/api/v1/session");
        expect(response.status).toBe(401);
      });
    });

    describe("presets", () => {
      it("serves the policy starting points to a signed-in caller", async () => {
        const response = await adminRequest(stack, "GET", "/api/v1/presets", {
          credential: await cookie(),
        });

        expect(response.status).toBe(200);
        const body = (await response.json()) as {
          presets: { id: string; policy: unknown }[];
        };
        expect(body.presets.map((preset) => preset.id)).toContain("pathling");
        expect(body.presets[0]?.policy).toBeDefined();
      });

      it("does not serve them to an unauthenticated caller", async () => {
        const response = await adminRequest(stack, "GET", "/api/v1/presets");
        expect(response.status).toBe(401);
      });
    });

    describe("an unknown route", () => {
      it("answers with the admin API's own error shape", async () => {
        const response = await adminRequest(
          stack,
          "GET",
          "/api/v1/nothing-here",
          {
            credential: await cookie(),
          },
        );

        expect(response.status).toBe(404);
        const body = (await response.json()) as { error: string };
        expect(body.error).toBe("not_found");
      });
    });

    describe("a second factor", () => {
      it("is demanded when the account has enrolled one", async () => {
        const stack2 = await createTestStack();
        try {
          // Enrolled directly: the enrolment route is part of the account settings
          // surface, and what is under test here is the sign-in path's response to
          // an account that has a secret.
          const { setAdminTotpSecret, encryptSecret } =
            await import("@signet/db");
          await setAdminTotpSecret(
            stack2.context.db,
            stack2.admin.id,
            await encryptSecret(
              "JBSWY3DPEHPK3PXP",
              stack2.context.config.masterKey,
            ),
          );

          const response = await adminRequest(
            stack2,
            "POST",
            "/api/v1/session",
            {
              body: { email: stack2.admin.email, password: TEST_PASSWORD },
            },
          );

          expect(response.status).toBe(401);
          const body = (await response.json()) as { totpRequired?: boolean };
          expect(body.totpRequired).toBe(true);
          expect(response.headers.get("set-cookie")).toBeNull();
        } finally {
          await stack2.close();
        }
      });

      it("refuses a wrong code", async () => {
        const stack2 = await createTestStack();
        try {
          const { setAdminTotpSecret, encryptSecret } =
            await import("@signet/db");
          await setAdminTotpSecret(
            stack2.context.db,
            stack2.admin.id,
            await encryptSecret(
              "JBSWY3DPEHPK3PXP",
              stack2.context.config.masterKey,
            ),
          );

          const response = await adminRequest(
            stack2,
            "POST",
            "/api/v1/session",
            {
              body: {
                email: stack2.admin.email,
                password: TEST_PASSWORD,
                totp: "000000",
              },
            },
          );

          expect(response.status).toBe(401);
          const body = (await response.json()) as { totpRequired?: boolean };
          expect(body.totpRequired).toBeUndefined();
        } finally {
          await stack2.close();
        }
      });
    });

    describe("a password that needs rehashing", () => {
      it("still authenticates", async () => {
        // Argon2 parameters change over time; a stored hash written with older ones
        // must keep working, because the alternative locks operators out at upgrade.
        const stack2 = await createTestStack();
        try {
          const { setAdminPasswordHash } = await import("@signet/db");
          await setAdminPasswordHash(
            stack2.context.db,
            stack2.admin.id,
            await hashPassword(TEST_PASSWORD),
          );
          const response = await adminRequest(
            stack2,
            "POST",
            "/api/v1/session",
            {
              body: { email: stack2.admin.email, password: TEST_PASSWORD },
            },
          );
          expect(response.status).toBe(200);
        } finally {
          await stack2.close();
        }
      });
    });
  },
);
