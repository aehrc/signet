/**
 * The `sweep` command, against a real database and both database identities.
 *
 * The unit suites cover the two decisions this command makes - what a grace
 * period string means, and what a connected role's observations amount to - and
 * both would keep passing if the command never issued a delete or never acted on
 * a verdict. So the assertions below are made against rows: seeded expired, swept
 * or not swept, and read back.
 *
 * Which identity the sweep is run as is the property that matters most, and it is
 * arranged rather than simulated. Run as the owning identity it deletes across
 * every tenant, which is what a maintenance job is for; run as the serving role
 * the policies hide every tenant-owned row, so it would report a clean database
 * that is in fact still growing. The second is the misconfiguration a nightly
 * CronJob would repeat unnoticed, so the command refuses it.
 *
 * Author: John Grimes
 */

import {
  clientScopeFromRow,
  createLaunchContext,
  findAccessToken,
  findLaunchContext,
  recordAccessToken,
  servingRoleUrl,
  withTenantScope,
} from "@signet/db";
import { afterAll, beforeAll, describe, expect, it } from "bun:test";

import { ConfigError } from "./config.js";
import { runSweepCommand } from "./sweep.js";
import { createTestStack, TEST_FHIR_BASE_URL } from "./test/harness.js";

import type { TestStack } from "./test/harness.js";

/**
 * The owning identity, which is the credential this command is meant to be given.
 *
 * Read from the environment here rather than through the harness, so that the scan
 * in `packages/db/src/test/ownerCredential.test.ts` sees this file for what it is:
 * a suite that acts as the identity the policies exempt, declared there with the
 * reason.
 */
const configuredOwnerUrl = process.env["SIGNET_TEST_DATABASE_URL"];

/** The same, non-optional: the suite below is skipped without it. */
const ownerUrl = configuredOwnerUrl ?? "";

/** Twenty-four hours, the command's default. */
const DAY_MS = 24 * 60 * 60 * 1000;

let counter = 0;

/** A value no other row in the shared database will have. */
function unique(): string {
  counter += 1;
  return `sweep-${String(process.pid)}-${String(counter)}`;
}

describe.skipIf(configuredOwnerUrl === undefined)("the sweep command", () => {
  let stack: TestStack;

  beforeAll(async () => {
    stack = await createTestStack();
  });

  afterAll(async () => {
    await stack.close();
  });

  /** One expired launch handle under the fixture tenant, and its handle hash. */
  async function seedExpiredLaunchContext(): Promise<string> {
    const handleHash = unique();
    await withTenantScope(stack.context.db, stack.scope, (bound) =>
      createLaunchContext(bound, {
        handleHash,
        context: {},
        expiresAt: new Date(Date.now() - 1000),
      }),
    );
    return handleHash;
  }

  /** An access token record that expired `agoMs` ago, and its `jti`. */
  async function seedExpiredAccessToken(agoMs: number): Promise<string> {
    const jti = unique();
    const scope = clientScopeFromRow(stack.scope, stack.symmetricClient);
    await withTenantScope(stack.context.db, scope, (bound) =>
      recordAccessToken(bound, {
        jti,
        subject: "user-1",
        scope: "patient/Observation.rs",
        issuer: stack.issuer,
        audience: TEST_FHIR_BASE_URL,
        expiresAt: new Date(Date.now() - agoMs),
      }),
    );
    return jti;
  }

  it("deletes expired rows across tenants as the owning identity", async () => {
    const handleHash = await seedExpiredLaunchContext();

    const counts = await runSweepCommand({
      ownerUrl,
      accessTokenGraceMs: DAY_MS,
    });

    expect(counts.launchContexts).toBeGreaterThan(0);
    expect(
      await withTenantScope(stack.context.db, stack.scope, (bound) =>
        findLaunchContext(bound, handleHash),
      ),
    ).toBeUndefined();
  });

  it("refuses the serving role rather than reporting a clean database", async () => {
    // The misconfiguration the check exists for. Every count would come back
    // zero, which is indistinguishable from a database with nothing to reclaim -
    // so a CronJob given the wrong credential would succeed nightly for months.
    const handleHash = await seedExpiredLaunchContext();

    const attempt = runSweepCommand({
      ownerUrl: servingRoleUrl(ownerUrl),
      accessTokenGraceMs: DAY_MS,
    });

    await expect(attempt).rejects.toThrow(ConfigError);
    await expect(attempt).rejects.toThrow(/SIGNET_DATABASE_OWNER_URL/);

    // And it refused before deleting anything, so the row is still there for a
    // correctly configured run.
    expect(
      await withTenantScope(stack.context.db, stack.scope, (bound) =>
        findLaunchContext(bound, handleHash),
      ),
    ).toBeDefined();
  });

  it("names the role it refused, and no part of a credential", async () => {
    let message = "";
    try {
      await runSweepCommand({
        ownerUrl: servingRoleUrl(ownerUrl),
        accessTokenGraceMs: DAY_MS,
      });
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }

    expect(message).toContain("signet_app_test");
    expect(message).not.toContain("://");
  });

  it("leaves an access token record inside the grace period alone", async () => {
    // A revocation list entry, not a runtime row. Deleting one an hour after it
    // expired answers a slightly late introspection as an unknown token rather
    // than as an inactive one with its metadata.
    const jti = await seedExpiredAccessToken(60 * 60 * 1000);

    await runSweepCommand({ ownerUrl, accessTokenGraceMs: DAY_MS });

    expect(
      await withTenantScope(stack.context.db, stack.scope, (bound) =>
        findAccessToken(bound, jti),
      ),
    ).toBeDefined();
  });

  it("deletes an access token record once the grace period has passed", async () => {
    const jti = await seedExpiredAccessToken(60 * 60 * 1000);

    const counts = await runSweepCommand({ ownerUrl, accessTokenGraceMs: 0 });

    expect(counts.accessTokens).toBeGreaterThan(0);
    expect(
      await withTenantScope(stack.context.db, stack.scope, (bound) =>
        findAccessToken(bound, jti),
      ),
    ).toBeUndefined();
  });

  it("reports what it verified and what it deleted", async () => {
    // The job's only output. An operator has to be able to read the identity it
    // acted as and the table that was growing out of a CronJob's log.
    await seedExpiredLaunchContext();
    const lines: string[] = [];

    await runSweepCommand({ ownerUrl, accessTokenGraceMs: DAY_MS }, (message) =>
      lines.push(message),
    );

    const output = lines.join("\n");
    expect(output).toContain("signet.sweep.identity-verified");
    expect(output).toContain("signet.sweep.completed");
    expect(output).toContain("launchContexts");
    expect(output).not.toContain("://");
  });
});
