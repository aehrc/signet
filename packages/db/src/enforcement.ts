/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Whether the policies actually bind this process.
 *
 * The tenant isolation policies constrain a connection only if the role it was
 * made by is subject to them. Postgres exempts a table's owner, and a role holding
 * `BYPASSRLS` is exempt everywhere, so the difference between a deployment that
 * enforces isolation in the database and one that merely has the policies
 * installed is a property of the credential - which is configuration, and
 * therefore something an operator can get wrong without any code being wrong.
 *
 * A deployment that cannot enforce must refuse to serve rather than serve
 * unprotected, so the server asks these questions before it listens. There are
 * four answers and three of them are refusals with different remedies, which is
 * why they are distinguished: an operator sent to the role documentation when the
 * real problem is an unmigrated database has been sent to the wrong fix.
 *
 * The check asks about role *membership* rather than comparing names.
 * `current_user = tableowner` is the wrong test, because a role that is a member of
 * the owning role inherits the owner's exemption while looking correct in every
 * other respect - see `pg_has_role` below.
 *
 * It also asks the catalogues rather than probing. Selecting from a covered table
 * and expecting no rows is inconclusive on a database that legitimately has no rows
 * yet, which is exactly the state of a freshly migrated deployment.
 *
 * Split into observing and deciding on purpose: the decision is a pure function
 * over the facts below, so every combination is asserted in
 * `./enforcement.test.ts` without a database, and only the asking needs one.
 *
 * Two decisions are made over the same observations, in opposite directions. The
 * server must be constrained by the policies, which {@link classifyEnforcement}
 * requires; the expiry sweep must be exempt from them, which
 * {@link classifySweepIdentity} requires. They are separate functions rather than
 * one with a flag, because a shared implementation is one edit away from checking
 * the wrong direction for one of its callers.
 *
 * Author: John Grimes
 */

import { sql } from "drizzle-orm";

import { RLS_TABLES } from "./rls.js";

import type { Executor } from "./repositories/executor.js";

/** What the check found out about one covered table. */
export interface TableObservation {
  readonly table: string;
  /** False when the table is not in the schema at all. */
  readonly present: boolean;
  /** Whether row-level security is enabled on it. */
  readonly policiesEnabled: boolean;
  /**
   * Whether those policies are forced, which binds the table's owner as well.
   *
   * Irrelevant to the server, whose role owns nothing either way, and decisive
   * for the sweep: a forced policy leaves `BYPASSRLS` as the only identity that
   * can act across tenants. See `force` in `./rls.ts`.
   */
  readonly policiesForced: boolean;
  /** The role that owns it, or null when the table is absent. */
  readonly owner: string | null;
  /**
   * Whether the connected role holds the owner's rights on it.
   *
   * True when it owns the table and also when it is a member of the role that
   * does, because membership inherits the exemption.
   */
  readonly roleHasOwnerRights: boolean;
  readonly readable: boolean;
  readonly writable: boolean;
}

/** Everything the check asked the database. */
export interface EnforcementObservations {
  /** The role the connection was made by. */
  readonly role: string;
  /** Whether that role holds `BYPASSRLS`. */
  readonly bypassesPolicies: boolean;
  readonly tables: readonly TableObservation[];
}

/** What the observations amount to. */
export type EnforcementOutcome =
  "healthy" | "schema-absent" | "role-exempt" | "role-under-privileged";

/** The check's conclusion, and what to report. */
export interface EnforcementVerdict {
  readonly outcome: EnforcementOutcome;
  /** The role that was verified, or the one that was refused. */
  readonly role: string;
  /** One line, naming what was found and what to do about it. */
  readonly message: string;
  /** Covered tables verified; zero on any refusal. */
  readonly tablesVerified: number;
  /** What was found, in the order found, for a caller that wants the detail. */
  readonly findings: readonly string[];
}

/** Renders a list for a message without letting it run away. */
function listOf(items: readonly string[], limit = 5): string {
  const shown = items.slice(0, limit).join(", ");
  return items.length > limit
    ? `${shown} and ${items.length - limit} more`
    : shown;
}

/** How a table's own exemption reads, which depends on how it was acquired. */
function exemptionFor(observed: TableObservation, role: string): string {
  return observed.owner === role
    ? `owns ${observed.table}`
    : `is a member of ${observed.owner ?? "an unknown role"}, which owns ${observed.table}`;
}

/**
 * Decides what the observations mean.
 *
 * The order the outcomes are tested in is part of the contract. An absent schema
 * is reported first because every other observation is then a consequence of it: a
 * table nobody has created is owned by nobody and readable by nobody. An exemption
 * is reported ahead of a missing grant because it is the one that would be serving
 * requests unprotected in the meantime.
 *
 * @param observations - What the database was asked.
 * @returns The outcome, with a message naming the remedy.
 * @throws {Error} When no covered table was observed, which would otherwise report
 *   healthy - and is indistinguishable from a query that silently matched nothing.
 * @example
 * ```ts
 * const verdict = classifyEnforcement(await observeEnforcement(db));
 * if (verdict.outcome !== "healthy") {
 *   throw new ConfigError(verdict.message);
 * }
 * ```
 */
export function classifyEnforcement(
  observations: EnforcementObservations,
): EnforcementVerdict {
  const { role, tables } = observations;
  if (tables.length === 0) {
    throw new Error(
      "The enforcement check observed no covered tables, so it can conclude nothing",
    );
  }

  const refusal = (
    outcome: EnforcementOutcome,
    message: string,
    findings: readonly string[],
  ): EnforcementVerdict => ({
    outcome,
    role,
    message,
    tablesVerified: 0,
    findings,
  });

  const absent = tables.filter((observed) => !observed.present);
  const unprotected = tables.filter(
    (observed) => observed.present && !observed.policiesEnabled,
  );
  if (absent.length > 0 || unprotected.length > 0) {
    const findings = [
      ...absent.map((observed) => `${observed.table} is absent`),
      ...unprotected.map(
        (observed) => `${observed.table} has row-level security disabled`,
      ),
    ];
    // Deliberately says nothing about roles: the remedy is to migrate, and a
    // message about credentials would send the operator somewhere else entirely.
    return refusal(
      "schema-absent",
      `Tenant isolation is not installed on this database: ${listOf(findings)}. Run the migrate command with the owning identity before starting the server.`,
      findings,
    );
  }

  const exemptions = [
    ...(observations.bypassesPolicies
      ? [`${role} holds BYPASSRLS, which exempts it from every policy`]
      : []),
    ...tables
      .filter((observed) => observed.roleHasOwnerRights)
      .map((observed) => `${role} ${exemptionFor(observed, role)}`),
  ];
  if (exemptions.length > 0) {
    return refusal(
      "role-exempt",
      `Database role ${role} is exempt from the tenant isolation policies: ${listOf(exemptions)}. Signet must connect as a role that owns none of its tables and holds no BYPASSRLS; see the tenant isolation section of docs/operations.md.`,
      exemptions,
    );
  }

  const unreachable = [
    ...tables
      .filter((observed) => !observed.readable)
      .map((observed) => `cannot read ${observed.table}`),
    ...tables
      .filter((observed) => !observed.writable)
      .map((observed) => `cannot insert into ${observed.table}`),
  ];
  if (unreachable.length > 0) {
    // Distinguished from an exemption because the remedies differ and because an
    // ungranted table otherwise presents as an empty result, which is what a
    // correctly enforced policy also looks like.
    return refusal(
      "role-under-privileged",
      `Database role ${role} is subject to the tenant isolation policies but ${listOf(unreachable)}. This is a missing grant rather than an exemption: re-run the migrate command with the owning identity, which grants the serving role its access.`,
      unreachable,
    );
  }

  return {
    outcome: "healthy",
    role,
    message: `Database role ${role} is subject to the tenant isolation policies on all ${tables.length} covered tables`,
    tablesVerified: tables.length,
    findings: [],
  };
}

/** What the sweep's identity check concluded. */
export type SweepIdentityOutcome =
  "healthy" | "schema-absent" | "role-constrained";

/** Whether the connection given to the sweep can act across tenants. */
export interface SweepIdentityVerdict {
  readonly outcome: SweepIdentityOutcome;
  /** The role the connection was made by. */
  readonly role: string;
  /** One line, naming what was found and what to do about it. */
  readonly message: string;
}

/**
 * Decides whether the connection the sweep was given can actually sweep.
 *
 * The mirror image of {@link classifyEnforcement}, and deliberately not a
 * parameter on it: the server must be constrained by the policies and the sweep
 * must be exempt from them, so the same observations mean opposite things and a
 * shared function with a flag would be one edit away from checking the wrong
 * direction.
 *
 * Exemption on *every* covered table is required, because partial exemption is the
 * outcome nobody can read: real counts for the tables the role could see, zero for
 * the rest, and a job that reports success on a database that is still growing.
 *
 * @param observations - What the sweep's own connection was asked.
 * @returns The outcome, with a message naming the remedy.
 * @throws {Error} When no covered table was observed, which would otherwise be a
 *   role exempt on all zero tables.
 * @example
 * ```ts
 * const verdict = classifySweepIdentity(await observeEnforcement(db));
 * if (verdict.outcome !== "healthy") {
 *   throw new ConfigError(verdict.message);
 * }
 * ```
 */
export function classifySweepIdentity(
  observations: EnforcementObservations,
): SweepIdentityVerdict {
  const { role, tables } = observations;
  if (tables.length === 0) {
    throw new Error(
      "The sweep's identity check observed no covered tables, so it can conclude nothing",
    );
  }

  // An absent schema first, for the reason it is first above: every other
  // observation is a consequence of it, and the remedy is to migrate rather than
  // to change a credential.
  const missing = tables
    .filter((observed) => !observed.present || !observed.policiesEnabled)
    .map((observed) =>
      observed.present
        ? `${observed.table} has row-level security disabled`
        : `${observed.table} is absent`,
    );
  if (missing.length > 0) {
    return {
      outcome: "schema-absent",
      role,
      message: `Tenant isolation is not installed on this database: ${listOf(missing)}. Run the migrate command with the owning identity before sweeping.`,
    };
  }

  if (observations.bypassesPolicies) {
    return {
      outcome: "healthy",
      role,
      message: `Database role ${role} holds BYPASSRLS, so the sweep reaches every tenant's expired rows`,
    };
  }

  // Ownership is not exemption where the policies are forced, which is the state
  // an ownership-only check would call healthy and then sweep nothing at all.
  const forced = tables
    .filter((observed) => observed.policiesForced)
    .map((observed) => observed.table);
  if (forced.length > 0) {
    return {
      outcome: "role-constrained",
      role,
      message: `The tenant isolation policies on ${listOf(forced)} are forced, which binds their owner as well, so a sweep run as ${role} would delete nothing there and report a clean database. A forced policy leaves BYPASSRLS as the only identity that can sweep: give SIGNET_DATABASE_OWNER_URL a role holding it.`,
    };
  }

  const hidden = tables
    .filter((observed) => !observed.roleHasOwnerRights)
    .map((observed) => observed.table);
  if (hidden.length > 0) {
    return {
      outcome: "role-constrained",
      role,
      message: `Database role ${role} is subject to the tenant isolation policies on ${listOf(hidden)}, so a sweep run as it would delete nothing there and report a clean database. The sweep acts across tenants and needs the identity that owns the schema: give it SIGNET_DATABASE_OWNER_URL, as the migration job is given it.`,
    };
  }

  return {
    outcome: "healthy",
    role,
    message: `Database role ${role} owns all ${String(tables.length)} covered tables, so the sweep reaches every tenant's expired rows`,
  };
}

/** One row of the catalogue query, before it is shaped into an observation. */
interface CatalogueRow {
  readonly table_name: string;
  readonly rls_enabled: boolean;
  readonly rls_forced: boolean;
  readonly owner: string;
  readonly owner_rights: boolean;
  readonly readable: boolean;
  readonly writable: boolean;
}

/**
 * Asks the database everything the decision needs.
 *
 * One statement, over `pg_class` and the privilege functions, so the answer cannot
 * be assembled from a database that changed underneath it. A covered table missing
 * from the result is reported as absent rather than as unreadable, which is what
 * lets an unmigrated deployment be told to migrate.
 *
 * @param db - The connection to ask about, which must be the one the server will
 *   serve on: every question is about `current_user`.
 * @param tables - The covered tables to check. Defaults to every table the
 *   policies are installed on.
 * @returns The observations, ready for {@link classifyEnforcement}.
 * @example
 * ```ts
 * const verdict = classifyEnforcement(await observeEnforcement(db));
 * ```
 */
export async function observeEnforcement(
  db: Executor,
  tables: readonly string[] = RLS_TABLES,
): Promise<EnforcementObservations> {
  const rows = (await db.execute(sql`
    select current_user::text as role,
           coalesce(r.rolbypassrls, false) as bypasses,
           c.relname::text as table_name,
           c.relrowsecurity as rls_enabled,
           c.relforcerowsecurity as rls_forced,
           pg_get_userbyid(c.relowner)::text as owner,
           pg_has_role(current_user, c.relowner, 'usage') as owner_rights,
           has_table_privilege(current_user, c.oid, 'select') as readable,
           has_table_privilege(current_user, c.oid, 'insert') as writable
      from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
      left join pg_roles r on r.rolname = current_user
     where n.nspname = 'public'
       and c.relkind = 'r'
       and c.relname = any(${sql.param(tables)})
  `)) as unknown as readonly (CatalogueRow & {
    readonly role: string;
    readonly bypasses: boolean;
  })[];

  const found = new Map(rows.map((row) => [row.table_name, row]));

  // The role and the bypass flag come from the same statement, so they describe
  // the connection that was actually observed. Read separately when no covered
  // table exists at all, since the query above then returns nothing.
  const [identity] = rows;
  const role = identity?.role ?? (await currentRole(db));
  const bypassesPolicies = identity?.bypasses ?? (await bypassesRls(db));

  return {
    role,
    bypassesPolicies,
    tables: tables.map((table) => {
      const row = found.get(table);
      return row === undefined
        ? {
            table,
            present: false,
            policiesEnabled: false,
            policiesForced: false,
            owner: null,
            roleHasOwnerRights: false,
            readable: false,
            writable: false,
          }
        : {
            table,
            present: true,
            policiesEnabled: row.rls_enabled,
            policiesForced: row.rls_forced,
            owner: row.owner,
            roleHasOwnerRights: row.owner_rights,
            readable: row.readable,
            writable: row.writable,
          };
    }),
  };
}

/** The connected role's name, for the case where no covered table exists. */
async function currentRole(db: Executor): Promise<string> {
  const rows = (await db.execute(
    sql`select current_user::text as role`,
  )) as unknown as readonly { readonly role: string }[];
  return rows[0]?.role ?? "unknown";
}

/** Whether the connected role holds `BYPASSRLS`, asked on its own. */
async function bypassesRls(db: Executor): Promise<boolean> {
  const rows = (await db.execute(sql`
    select coalesce(bool_or(rolbypassrls), false) as bypasses
      from pg_roles where rolname = current_user
  `)) as unknown as readonly { readonly bypasses: boolean }[];
  return rows[0]?.bypasses ?? false;
}
