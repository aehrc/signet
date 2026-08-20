/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { classifyEnforcement, classifySweepIdentity } from "./enforcement.js";

import type {
  EnforcementObservations,
  TableObservation,
} from "./enforcement.js";

const ROLE = "signet_app";
const OWNER = "signet";

/** A covered table as the check finds it in a correctly provisioned database. */
function healthyTable(table: string): TableObservation {
  return {
    table,
    present: true,
    policiesEnabled: true,
    policiesForced: false,
    owner: OWNER,
    roleHasOwnerRights: false,
    readable: true,
    writable: true,
  };
}

/** Observations of a correctly provisioned database, before any modification. */
function healthyObservations(
  overrides: Partial<EnforcementObservations> = {},
): EnforcementObservations {
  return {
    role: ROLE,
    bypassesPolicies: false,
    tables: ["tenants", "endpoints", "audit_events"].map(healthyTable),
    ...overrides,
  };
}

/** The same observations with one table replaced. */
function withTable(
  observations: EnforcementObservations,
  table: string,
  changes: Partial<TableObservation>,
): EnforcementObservations {
  return {
    ...observations,
    tables: observations.tables.map((observed) =>
      observed.table === table ? { ...observed, ...changes } : observed,
    ),
  };
}

describe("classifyEnforcement", () => {
  it("reports healthy for a non-owning role that can reach every covered table", () => {
    const verdict = classifyEnforcement(healthyObservations());

    expect(verdict.outcome).toBe("healthy");
    // Visibility: a successful start has to say what was verified, or the check
    // is indistinguishable from not having run.
    expect(verdict.role).toBe(ROLE);
    expect(verdict.message).toContain(ROLE);
    expect(verdict.message).toContain("3");
  });

  it("reports the schema absent when a covered table does not exist", () => {
    const verdict = classifyEnforcement(
      withTable(healthyObservations(), "endpoints", {
        present: false,
        policiesEnabled: false,
        owner: null,
        readable: false,
        writable: false,
      }),
    );

    expect(verdict.outcome).toBe("schema-absent");
    expect(verdict.message).toContain("endpoints");
    // The remedy, and deliberately not a word about roles: an unmigrated database
    // sent to the role documentation is an operator sent to the wrong fix.
    expect(verdict.message).toContain("migrate");
    expect(verdict.message).not.toContain(ROLE);
  });

  it("reports the schema absent when a table has lost its policies", () => {
    // A table that exists but has row-level security disabled is not a role
    // problem: the policies migration has not been applied, or has been undone.
    const verdict = classifyEnforcement(
      withTable(healthyObservations(), "tenants", { policiesEnabled: false }),
    );

    expect(verdict.outcome).toBe("schema-absent");
    expect(verdict.message).toContain("tenants");
    expect(verdict.message).toContain("migrate");
  });

  it("refuses a role that can bypass the policies", () => {
    const verdict = classifyEnforcement(
      healthyObservations({ bypassesPolicies: true }),
    );

    expect(verdict.outcome).toBe("role-exempt");
    expect(verdict.message).toContain(ROLE);
    expect(verdict.message).toContain("BYPASSRLS");
  });

  it("refuses a role that owns a covered table, naming the table", () => {
    const verdict = classifyEnforcement(
      withTable(healthyObservations(), "endpoints", {
        owner: ROLE,
        roleHasOwnerRights: true,
      }),
    );

    expect(verdict.outcome).toBe("role-exempt");
    expect(verdict.message).toContain(ROLE);
    expect(verdict.message).toContain("endpoints");
    expect(verdict.message).toContain("owns");
  });

  it("treats membership of an owning role as an exemption", () => {
    // The reason the check asks pg_has_role rather than comparing names: a role
    // that is a member of the owner inherits the owner's exemption, and a
    // deployment configured that way looks correct in every other respect.
    const verdict = classifyEnforcement(
      withTable(healthyObservations(), "audit_events", {
        roleHasOwnerRights: true,
      }),
    );

    expect(verdict.outcome).toBe("role-exempt");
    expect(verdict.message).toContain("member");
    expect(verdict.message).toContain(OWNER);
    expect(verdict.message).toContain("audit_events");
  });

  it("refuses an under-privileged role, distinguishing it from an exemption", () => {
    const verdict = classifyEnforcement(
      withTable(healthyObservations(), "audit_events", { readable: false }),
    );

    expect(verdict.outcome).toBe("role-under-privileged");
    expect(verdict.message).toContain(ROLE);
    expect(verdict.message).toContain("audit_events");
    // The distinction is the point: a missing grant presents as an empty result
    // unless somebody says otherwise, and its remedy is not the exemption's.
    expect(verdict.message).toContain("grant");
    expect(verdict.message).not.toContain("BYPASSRLS");
  });

  it("refuses a role that can read a covered table but not write it", () => {
    const verdict = classifyEnforcement(
      withTable(healthyObservations(), "tenants", { writable: false }),
    );

    expect(verdict.outcome).toBe("role-under-privileged");
    expect(verdict.message).toContain("tenants");
  });

  it("reports an exemption ahead of a missing grant", () => {
    // Both need fixing, and the exemption is the one that is serving requests
    // unprotected in the meantime.
    const exempt = withTable(
      healthyObservations({ bypassesPolicies: true }),
      "tenants",
      { readable: false },
    );

    expect(classifyEnforcement(exempt).outcome).toBe("role-exempt");
  });

  it("reports an absent schema ahead of everything else", () => {
    // A missing table is unreadable and unowned by anybody, so every other
    // observation is a consequence of the same cause.
    const unmigrated: EnforcementObservations = {
      role: ROLE,
      bypassesPolicies: true,
      tables: [
        {
          table: "tenants",
          present: false,
          policiesEnabled: false,
          policiesForced: false,
          owner: null,
          roleHasOwnerRights: false,
          readable: false,
          writable: false,
        },
      ],
    };

    expect(classifyEnforcement(unmigrated).outcome).toBe("schema-absent");
  });

  it("never puts a connection string in a message", () => {
    // A role name is what an operator needs in order to act; a credential is not,
    // and this message is written to the logs on every start.
    const verdicts = [
      classifyEnforcement(healthyObservations()),
      classifyEnforcement(healthyObservations({ bypassesPolicies: true })),
      classifyEnforcement(
        withTable(healthyObservations(), "tenants", { readable: false }),
      ),
      classifyEnforcement(
        withTable(healthyObservations(), "tenants", { present: false }),
      ),
    ];

    for (const verdict of verdicts) {
      expect(verdict.message).not.toContain("://");
      expect(verdict.message).not.toContain("@");
    }
  });

  it("refuses observations that cover no table at all", () => {
    // Guards the guard: an empty table list would otherwise report healthy, which
    // is exactly what a check whose query silently returned nothing would do.
    expect(() =>
      classifyEnforcement(healthyObservations({ tables: [] })),
    ).toThrow(/no covered tables/i);
  });
});

/** Observations of the identity the sweep is meant to be run with. */
function ownerObservations(
  overrides: Partial<EnforcementObservations> = {},
): EnforcementObservations {
  return {
    role: OWNER,
    bypassesPolicies: false,
    tables: ["tenants", "endpoints", "audit_events"].map((table) => ({
      ...healthyTable(table),
      roleHasOwnerRights: true,
    })),
    ...overrides,
  };
}

describe("classifySweepIdentity", () => {
  it("reports healthy for the role that owns every covered table", () => {
    const verdict = classifySweepIdentity(ownerObservations());

    expect(verdict.outcome).toBe("healthy");
    expect(verdict.role).toBe(OWNER);
    // The identity actually used has to be readable out of the job's log, or a
    // sweep that reclaimed nothing is indistinguishable from one that did.
    expect(verdict.message).toContain(OWNER);
  });

  it("reports healthy for a role holding BYPASSRLS", () => {
    // The other way to be exempt. An operator may legitimately give a
    // maintenance job such a role rather than the identity that owns the schema.
    const verdict = classifySweepIdentity(
      ownerObservations({
        role: ROLE,
        bypassesPolicies: true,
        tables: ["tenants", "endpoints"].map(healthyTable),
      }),
    );

    expect(verdict.outcome).toBe("healthy");
  });

  it("refuses the serving role, which would delete nothing", () => {
    const verdict = classifySweepIdentity(
      ownerObservations({
        role: ROLE,
        tables: ["tenants", "endpoints", "audit_events"].map(healthyTable),
      }),
    );

    expect(verdict.outcome).toBe("role-constrained");
    expect(verdict.message).toContain(ROLE);
    // Names the remedy, which is a credential rather than a migration.
    expect(verdict.message).toContain("SIGNET_DATABASE_OWNER_URL");
  });

  it("refuses a role exempt on only some covered tables", () => {
    // The dangerous middle: a partial sweep reports real counts for the tables it
    // could see and zero for the rest, which reads as a healthy job on a database
    // that is quietly still growing.
    const verdict = classifySweepIdentity(
      withTable(ownerObservations(), "endpoints", {
        roleHasOwnerRights: false,
      }),
    );

    expect(verdict.outcome).toBe("role-constrained");
    expect(verdict.message).toContain("endpoints");
  });

  it("refuses an owner that a forced policy binds anyway", () => {
    // `alter table ... force row level security` subjects the owner to the
    // policies too, which is exactly the state ownership alone cannot see: the
    // sweep would delete nothing and report zero, which is what the check exists
    // to make impossible. See `force` in `./rls.ts`.
    const verdict = classifySweepIdentity(
      withTable(ownerObservations(), "endpoints", { policiesForced: true }),
    );

    expect(verdict.outcome).toBe("role-constrained");
    expect(verdict.message).toContain("endpoints");
    expect(verdict.message).toContain("force");
  });

  it("accepts BYPASSRLS against a forced policy", () => {
    // The one identity a forced policy does not bind, and the reason `force` is
    // documented as requiring it.
    const forced = withTable(
      ownerObservations({ bypassesPolicies: true }),
      "endpoints",
      { policiesForced: true },
    );

    expect(classifySweepIdentity(forced).outcome).toBe("healthy");
  });

  it("reports a table that has lost its policies as an absent schema", () => {
    // The other half of the same filter as the case below: present, but with
    // row-level security turned off. The remedy is still to migrate.
    const verdict = classifySweepIdentity(
      withTable(ownerObservations(), "tenants", { policiesEnabled: false }),
    );

    expect(verdict.outcome).toBe("schema-absent");
    expect(verdict.message).toContain("tenants");
    expect(verdict.message).toContain("migrate");
  });

  it("reports the schema absent ahead of anything about the role", () => {
    // The remedy is to migrate. A message about credentials would send the
    // operator to rotate a role that is perfectly correct.
    const verdict = classifySweepIdentity(
      withTable(ownerObservations(), "endpoints", {
        present: false,
        policiesEnabled: false,
        owner: null,
        roleHasOwnerRights: false,
        readable: false,
        writable: false,
      }),
    );

    expect(verdict.outcome).toBe("schema-absent");
    expect(verdict.message).toContain("endpoints");
    expect(verdict.message).not.toContain("SIGNET_DATABASE_OWNER_URL");
  });

  it("never puts a connection string in a message", () => {
    const verdicts = [
      classifySweepIdentity(ownerObservations()),
      classifySweepIdentity(
        ownerObservations({ role: ROLE, tables: [healthyTable("tenants")] }),
      ),
      classifySweepIdentity(
        withTable(ownerObservations(), "tenants", { present: false }),
      ),
    ];

    for (const verdict of verdicts) {
      expect(verdict.message).not.toContain("://");
      expect(verdict.message).not.toContain("@");
    }
  });

  it("refuses observations that cover no table at all", () => {
    // Guards the guard, for the same reason the check above does: an empty list
    // would otherwise be a role exempt on all zero tables.
    expect(() =>
      classifySweepIdentity(ownerObservations({ tables: [] })),
    ).toThrow(/no covered tables/i);
  });
});
