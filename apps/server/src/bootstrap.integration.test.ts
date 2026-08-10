/**
 * The bootstrap command.
 *
 * Two properties matter and neither can be checked without a database: that it
 * produces an account which can actually sign in and reach the tenant, and that
 * running it twice changes nothing - including not resetting the password, which is
 * what would happen if a Helm hook re-ran on every upgrade and the command were
 * careless.
 *
 * Author: John Grimes
 */

import {
  deleteAdminUser,
  deleteTenant,
  resolveTenantScope,
  servingRoleUrl,
  withTenantScope,
} from "@signet/db";
import { afterAll, beforeAll, describe, expect, it } from "bun:test";

import { bootstrapOptionsFrom, runBootstrapCommand } from "./bootstrap.js";
import { adminRequest } from "./test/adminApi.js";
import { createTestStack, testDatabaseUrl } from "./test/harness.js";

import type { TestStack } from "./test/harness.js";

describe("bootstrapOptionsFrom", () => {
  const complete = {
    SIGNET_BOOTSTRAP_TENANT: "demo",
    SIGNET_BOOTSTRAP_EMAIL: "ops@example.org",
    SIGNET_BOOTSTRAP_PASSWORD: "a-sufficiently-long-password",
  };

  it("reads the required variables", () => {
    const options = bootstrapOptionsFrom(complete, "postgres://x/y");
    expect(options.tenantSlug).toBe("demo");
    expect(options.email).toBe("ops@example.org");
    expect(options.databaseUrl).toBe("postgres://x/y");
  });

  it("defaults the display names to something usable", () => {
    const options = bootstrapOptionsFrom(complete, "postgres://x/y");
    expect(options.tenantName).toBe("demo");
    expect(options.displayName).toBe("ops@example.org");
  });

  it("honours the optional names", () => {
    const options = bootstrapOptionsFrom(
      {
        ...complete,
        SIGNET_BOOTSTRAP_TENANT_NAME: "Demonstration",
        SIGNET_BOOTSTRAP_NAME: "Operations",
      },
      "postgres://x/y",
    );
    expect(options.tenantName).toBe("Demonstration");
    expect(options.displayName).toBe("Operations");
  });

  it("names the variable that is missing", () => {
    expect(() =>
      bootstrapOptionsFrom(
        { ...complete, SIGNET_BOOTSTRAP_EMAIL: undefined },
        "postgres://x/y",
      ),
    ).toThrow(/SIGNET_BOOTSTRAP_EMAIL/);
  });

  it("treats a blank variable as missing", () => {
    expect(() =>
      bootstrapOptionsFrom(
        { ...complete, SIGNET_BOOTSTRAP_TENANT: "   " },
        "postgres://x/y",
      ),
    ).toThrow(/SIGNET_BOOTSTRAP_TENANT/);
  });

  it("refuses a password too short to be worth having", () => {
    expect(() =>
      bootstrapOptionsFrom(
        { ...complete, SIGNET_BOOTSTRAP_PASSWORD: "short" },
        "postgres://x/y",
      ),
    ).toThrow(/at least 12/);
  });
});

describe.skipIf(testDatabaseUrl === undefined)("the bootstrap command", () => {
  let stack: TestStack;
  const suffix = String(process.pid);
  const tenantSlug = `bootstrap-${suffix}`;
  const email = `bootstrap-${suffix}@signet.test`;
  const password = "a-sufficiently-long-password";

  /**
   * The command's options, built when a test asks for them rather than up front.
   *
   * A `describe` body runs even when `skipIf` has decided to skip its tests, so
   * deriving a serving role here from an unset SIGNET_TEST_DATABASE_URL threw and
   * failed the whole run - which is the opposite of the quiet skip the suite
   * documents.
   *
   * The serving credential is the point of the derivation: creating the first tenant
   * and its first owner must be possible without the owning identity, or a deployment
   * would have to hand the migration credential to a hook Job that also serves
   * requests.
   */
  const options = () => ({
    databaseUrl: servingRoleUrl(testDatabaseUrl ?? ""),
    tenantSlug,
    tenantName: "Bootstrapped",
    email,
    password,
    displayName: "Bootstrap Operator",
  });

  beforeAll(async () => {
    // Only for the app instance and the migrated schema; the command works
    // against the database directly, as it does in a Helm hook.
    stack = await createTestStack();
  });

  afterAll(async () => {
    const scope = await resolveTenantScope(stack.context.db, tenantSlug);
    if (scope !== undefined) {
      await withTenantScope(stack.context.db, scope, (bound) =>
        deleteTenant(bound),
      );
    }
    const { findAdminUserByEmail } = await import("@signet/db");
    const user = await findAdminUserByEmail(stack.context.db, email);
    if (user !== undefined) {
      await deleteAdminUser(stack.context.db, user.id);
    }
    await stack.close();
  });

  it("creates a tenant and an owner who can sign in and reach it", async () => {
    const outcome = await runBootstrapCommand(options(), () => undefined);
    expect(outcome).toEqual({
      tenantCreated: true,
      adminCreated: true,
      membershipGranted: true,
    });

    const signIn = await adminRequest(stack, "POST", "/api/v1/session", {
      body: { email: email, password: password },
    });
    expect(signIn.status).toBe(200);

    const cookie = (signIn.headers.get("set-cookie") ?? "").split(";", 1)[0];
    const tenant = await adminRequest(
      stack,
      "GET",
      `/api/v1/tenants/${tenantSlug}`,
      { credential: { cookie: cookie ?? "" } },
    );
    expect(tenant.status).toBe(200);
    const body = (await tenant.json()) as { role: string };
    expect(body.role).toBe("owner");
  });

  it("is idempotent, and does not reset the password", async () => {
    const again = await runBootstrapCommand(
      { ...options(), password: "a-completely-different-password" },
      () => undefined,
    );
    expect(again).toEqual({
      tenantCreated: false,
      adminCreated: false,
      membershipGranted: false,
    });

    // The original password still works, and the new one does not: a re-run of
    // the installer must not silently rotate an operator's credential.
    const original = await adminRequest(stack, "POST", "/api/v1/session", {
      body: { email: email, password: password },
    });
    expect(original.status).toBe(200);

    const replaced = await adminRequest(stack, "POST", "/api/v1/session", {
      body: {
        email: email,
        password: "a-completely-different-password",
      },
    });
    expect(replaced.status).toBe(401);
  });
});
