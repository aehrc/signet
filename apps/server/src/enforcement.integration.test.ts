/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The startup check, against the four database states it exists to tell apart.
 *
 * `packages/db/src/enforcement.test.ts` asserts the decision over made-up
 * observations, and would keep passing if the observations were never made or the
 * verdict never acted on. This suite is the other half: four real identities on a
 * real database, each connected as, each producing the outcome an operator would
 * be told about.
 *
 * The four are arranged rather than simulated, because each is a distinct way a
 * deployment goes wrong and only the database can say whether it has gone wrong
 * that way:
 *
 *   - the owning identity, which Postgres exempts from its own tables' policies;
 *   - a role holding `BYPASSRLS`, exempt everywhere, and otherwise granted exactly
 *     what the serving role is granted, so the bypass is the only fault;
 *   - a role subject to the policies with no grants at all, which presents as an
 *     empty result and is a different problem with a different remedy;
 *   - an empty database, which is a deployment whose migration has not run.
 *
 * The last is a database of its own rather than the shared test database with its
 * tables dropped: every other suite is using those tables.
 *
 * Creating a role with `BYPASSRLS` requires the configured identity to hold it,
 * and creating a database requires `CREATEDB`. Both hold for the throwaway
 * superuser the compose stack and CI provide; a test database configured with less
 * fails here loudly rather than skipping.
 *
 * Author: John Grimes
 */

import {
  applyServingRolePrivileges,
  createDatabase,
  createProbeRole,
  createScratchDatabase,
  databaseUrlWith,
  dropProbeRole,
  dropScratchDatabase,
  RLS_TABLES,
  SERVING_TEST_ROLE,
  servingRoleUrl,
} from "@signet/db";
import { afterAll, beforeAll, describe, expect, it, spyOn } from "bun:test";

import { ConfigError } from "./config.js";
import { verifyEnforcement } from "./enforcement.js";
import { ensureTestSchema, testDatabaseUrl } from "./test/harness.js";

import type { Database, DatabaseHandle } from "@signet/db";

/**
 * The password the probe roles are created with.
 *
 * Deliberately unlike anything else here, so that asserting no message discloses
 * part of a connection string is a real assertion: on the databases this suite
 * runs against the owning identity's password happens to equal its role name, and
 * a role name is not a credential.
 */
const PROBE_PASSWORD = "probe-credential-never-in-a-message";

/** Unique per run, so a second `bun test` against the same server cannot collide. */
const suffix = String(process.pid);

/** Exempt everywhere, and granted everything the serving role is granted. */
const BYPASS_ROLE = `signet_bypass_test_${suffix}`;

/** Subject to the policies, granted nothing. */
const UNGRANTED_ROLE = `signet_ungranted_test_${suffix}`;

/** A database on which no migration has been run. */
const ABSENT_DATABASE = `signet_absent_test_${suffix}`;

/** The first covered table, named in a refusal about an unreachable one. */
const FIRST_COVERED_TABLE = RLS_TABLES[0] ?? "tenants";

describe.skipIf(testDatabaseUrl === undefined)(
  "the startup enforcement check",
  () => {
    const ownerUrl = testDatabaseUrl ?? "";
    /** The credential parts no message may disclose any of. */
    const secrets: string[] = [PROBE_PASSWORD, "postgres://"];
    let owner: DatabaseHandle;
    /** Every handle opened, so teardown can close them all. */
    const opened: DatabaseHandle[] = [];

    /** Opens a connection and remembers it, so teardown can close it. */
    function connect(url: string): Database {
      const handle = createDatabase({ url, maxConnections: 1 });
      opened.push(handle);
      return handle.db;
    }

    /**
     * Asserts a message gives away no part of a connection string.
     *
     * Applied to every message the check produces, refusal and success alike. A
     * role name is what an operator needs in order to act and is not a credential;
     * a password, a host or a whole URL is neither.
     */
    function expectNoDisclosure(message: string): void {
      for (const secret of secrets) {
        expect(message, `disclosed ${secret}`).not.toContain(secret);
      }
    }

    /**
     * Runs the check, expecting it to refuse, and returns its message.
     *
     * Anything other than a `ConfigError` is rethrown: the refusal has to arrive on
     * the path `apps/server/src/index.ts` turns into exit 1, not merely as some
     * failure.
     */
    async function refusalFor(db: Database): Promise<string> {
      const outcome = await verifyEnforcement(db, "info").then(
        (verdict) => verdict,
        (error: unknown) => error,
      );

      expect(
        outcome,
        `expected a refusal, got ${JSON.stringify(outcome)}`,
      ).toBeInstanceOf(ConfigError);
      const message = (outcome as ConfigError).message;
      expectNoDisclosure(message);
      return message;
    }

    beforeAll(async () => {
      await ensureTestSchema(ownerUrl);

      owner = createDatabase({ url: ownerUrl, maxConnections: 1 });

      const url = new URL(ownerUrl);
      secrets.push(url.host, url.hostname);
      if (url.port.length > 0) {
        secrets.push(url.port);
      }

      await createProbeRole(owner.db, BYPASS_ROLE, {
        password: PROBE_PASSWORD,
        bypassesPolicies: true,
      });
      // Granted exactly what a correct serving role is granted, so the bypass is
      // the only thing separating this identity from the healthy one. Ungranted, it
      // would be refused for being under-privileged and the assertion would pass
      // for the wrong reason.
      await applyServingRolePrivileges(owner.db, BYPASS_ROLE);

      await createProbeRole(owner.db, UNGRANTED_ROLE, {
        password: PROBE_PASSWORD,
      });

      // Dropped first in case an interrupted run left one behind: a scratch
      // database already carrying a schema would be reported healthy.
      await dropScratchDatabase(owner.db, ABSENT_DATABASE);
      await createScratchDatabase(owner.db, ABSENT_DATABASE);
    });

    afterAll(async () => {
      for (const handle of opened) {
        await handle.close();
      }
      await dropScratchDatabase(owner.db, ABSENT_DATABASE);
      await dropProbeRole(owner.db, BYPASS_ROLE);
      await dropProbeRole(owner.db, UNGRANTED_ROLE);
      await owner.close();
    });

    it("refuses the identity that owns the tables, naming the exemption", async () => {
      // The credential a deployment must not give the server, and the one that is
      // indistinguishable from a correct one in every other respect.
      const message = await refusalFor(connect(ownerUrl));

      expect(message).toMatch(/is exempt from the tenant isolation policies/);
      // The specific exemption, not just the conclusion: an operator told a role is
      // unsuitable has been told nothing they can act on.
      expect(message).toMatch(new RegExp(`owns ${FIRST_COVERED_TABLE}`));
      expect(message).toContain("owns none of its tables");
      expect(message).toContain("docs/operations.md");
      // Where the role came from, since that is the thing to change.
      expect(message).toContain("SIGNET_DATABASE_URL");
    });

    it("refuses a role holding BYPASSRLS", async () => {
      const message = await refusalFor(
        connect(
          databaseUrlWith(ownerUrl, {
            user: BYPASS_ROLE,
            password: PROBE_PASSWORD,
          }),
        ),
      );

      expect(message).toContain(BYPASS_ROLE);
      expect(message).toContain("BYPASSRLS");
      expect(message).toMatch(/is exempt from the tenant isolation policies/);
    });

    it("refuses an under-privileged role, distinguishing it from an exemption", async () => {
      const message = await refusalFor(
        connect(
          databaseUrlWith(ownerUrl, {
            user: UNGRANTED_ROLE,
            password: PROBE_PASSWORD,
          }),
        ),
      );

      expect(message).toContain(UNGRANTED_ROLE);
      // The unreachable table by name. A missing grant presents as an empty
      // result, which is what a working policy also looks like, so the message has
      // to say which table and that a grant is what is missing.
      expect(message).toContain(FIRST_COVERED_TABLE);
      expect(message).toContain("missing grant");
      expect(message).toContain("migrate");
      expect(message).not.toMatch(/is exempt from/);
    });

    it("refuses an unmigrated database by naming the schema, not the role", async () => {
      const message = await refusalFor(
        connect(
          databaseUrlWith(servingRoleUrl(ownerUrl), {
            database: ABSENT_DATABASE,
          }),
        ),
      );

      expect(message).toContain("Tenant isolation is not installed");
      expect(message).toContain(`${FIRST_COVERED_TABLE} is absent`);
      expect(message).toContain("migrate");
      // The remedy is to migrate. A message about credentials would send the
      // operator to rotate a role that is perfectly correct.
      expect(message).not.toContain(SERVING_TEST_ROLE);
      expect(message).not.toContain("SIGNET_DATABASE_URL");
    });

    it("accepts the serving role and reports what it verified", async () => {
      const lines: string[] = [];
      const log = spyOn(console, "log").mockImplementation(
        (...written: unknown[]) => {
          lines.push(String(written[0]));
        },
      );

      // Restored in `finally` rather than through a teardown hook: an assertion
      // below that failed while `console.log` was still captured would take the
      // reporter's own output with it.
      let verdict: Awaited<ReturnType<typeof verifyEnforcement>>;
      try {
        verdict = await verifyEnforcement(
          connect(servingRoleUrl(ownerUrl)),
          "info",
        );
      } finally {
        log.mockRestore();
      }

      expect(verdict.outcome).toBe("healthy");
      expect(verdict.role).toBe(SERVING_TEST_ROLE);
      // Every covered table, not a sample: a check that verified one table and
      // reported success is the same false assurance as no check at all.
      expect(verdict.tablesVerified).toBe(RLS_TABLES.length);
      expectNoDisclosure(verdict.message);

      // Reported on success as well as failure, and through the structured log
      // path, so an operator can see which identity a running deployment verified.
      const records = lines.map((line) => {
        expectNoDisclosure(line);
        return JSON.parse(line) as Record<string, unknown>;
      });
      const record = records.find(
        (entry) => entry["message"] === "signet.enforcement.verified",
      );

      expect(record).toBeDefined();
      expect(record?.["level"]).toBe("info");
      expect(record?.["role"]).toBe(SERVING_TEST_ROLE);
      expect(record?.["tablesVerified"]).toBe(RLS_TABLES.length);
    });
  },
);
