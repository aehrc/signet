/**
 * The statements that give the serving role exactly what it needs.
 *
 * These assert the *generator*. That is a weaker claim than it looks, and the
 * companion suites say so: `privileges.migration.test.ts` asserts the routines
 * are in the migration folder, and the integration suite asserts the `migrate`
 * command actually applies what is generated here. A generator whose output
 * nothing runs is the failure `rls.migration.test.ts` was written to catch, and
 * the same failure is available to this file.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "vitest";

import {
  PRIVILEGED_ROUTINES,
  servingRolePrivilegeStatements,
} from "./privileges.js";

/** A representative role name. Signet does not fix it; the operator chooses. */
const ROLE = "signet_app";

/** The statements for {@link ROLE}, lowercased for matching. */
const statements = servingRolePrivilegeStatements(ROLE).map((statement) =>
  statement.toLowerCase(),
);

/** Every statement as one body, for "does it appear anywhere" assertions. */
const script = statements.join("\n");

describe("the declared privileged routines", () => {
  it("declares the three the design names, and no more", () => {
    // The set is the reviewable surface. A fourth routine is a widening of what
    // the application can do without declaring a tenant, so it has to be an edit
    // to this list rather than a grant somebody added to a migration.
    expect(Object.keys(PRIVILEGED_ROUTINES).toSorted()).toEqual([
      "signet_tenant_id_for_api_token(text)",
      "signet_tenant_id_for_slug(text)",
      "signet_tenant_ids_for_admin(uuid)",
    ]);
  });

  it("records a justification for each", () => {
    for (const [routine, justification] of Object.entries(
      PRIVILEGED_ROUTINES,
    )) {
      expect(justification.length, `${routine} is unjustified`).toBeGreaterThan(
        40,
      );
    }
  });
});

describe("servingRolePrivilegeStatements - table access", () => {
  it("grants usage on the schema", () => {
    // Without this every table grant below is unreachable: Postgres requires
    // schema usage before any object in it can be named.
    expect(statements).toContain(`grant usage on schema public to "${ROLE}"`);
  });

  it("grants the four statements the server issues", () => {
    expect(statements).toContain(
      `grant select, insert, update, delete on all tables in schema public to "${ROLE}"`,
    );
  });

  it("sets default privileges so a later table cannot ship ungranted", () => {
    // The backstop for a migration that adds a table and nobody remembering to
    // grant it. The reachability test in the integration suite is the backstop
    // for the case this misses - a table created by a different owning role.
    expect(script).toContain("alter default privileges in schema public");
    expect(script).toContain(
      `grant select, insert, update, delete on tables to "${ROLE}"`,
    );
  });
});

describe("servingRolePrivilegeStatements - the audit trail", () => {
  it("revokes update and delete on audit_events", () => {
    // The constitution requires the trail to be append-only. Until now that was
    // a convention only code review enforced; here it becomes a privilege the
    // database refuses to violate.
    expect(statements).toContain(
      `revoke update, delete on audit_events from "${ROLE}"`,
    );
  });

  it("revokes after the blanket grant, not before it", () => {
    // Order is the whole property. A revoke issued before `grant ... on all
    // tables` is undone by it, and the result looks identical in a diff.
    const granted = statements.findIndex((statement) =>
      statement.startsWith(
        "grant select, insert, update, delete on all tables",
      ),
    );
    const revoked = statements.findIndex((statement) =>
      statement.startsWith("revoke update, delete on audit_events"),
    );

    expect(granted).toBeGreaterThanOrEqual(0);
    expect(revoked).toBeGreaterThan(granted);
  });
});

describe("servingRolePrivilegeStatements - the privileged routines", () => {
  it("grants execute for exactly the declared set", () => {
    const granted = statements
      .map((statement) =>
        /^grant execute on function (?<routine>.+) to "/.exec(statement),
      )
      .map((match) => match?.groups?.["routine"])
      .filter((routine): routine is string => routine !== undefined);

    // Equality, not containment: an omission leaves a resolver unable to run,
    // and an addition is an undeclared widening of the exemption.
    expect(granted.toSorted()).toEqual(
      Object.keys(PRIVILEGED_ROUTINES).toSorted(),
    );
  });

  it("grants each one to the serving role and nobody else", () => {
    for (const routine of Object.keys(PRIVILEGED_ROUTINES)) {
      expect(statements).toContain(
        `grant execute on function ${routine} to "${ROLE}"`,
      );
    }
  });
});

describe("servingRolePrivilegeStatements - the role name", () => {
  it("quotes the role as an identifier every time it appears", () => {
    const mentioning = statements.filter((statement) =>
      statement.includes(ROLE),
    );

    // Every mention is a quoted identifier. A bare `to signet_app` happens to
    // work for a lower-case name and breaks for the mixed-case one a managed
    // database hands out, which is the kind of failure that only shows up in
    // somebody else's deployment.
    expect(mentioning.length).toBeGreaterThan(0);
    expect(
      mentioning.filter((statement) => !statement.includes(`"${ROLE}"`)),
    ).toEqual([]);
  });

  it("never puts the role in a value position", () => {
    // None of these statements needs a string literal, so the presence of one
    // would mean a name had been interpolated where a value belongs.
    for (const statement of statements) {
      expect(statement).not.toContain("'");
    }
  });

  it("escapes a quote in the role name rather than closing the identifier", () => {
    const awkward = servingRolePrivilegeStatements('we"ird');

    // Postgres escapes an embedded double quote by doubling it. Emitting the
    // name unescaped would end the identifier early and leave the remainder of
    // the name as SQL.
    expect(awkward.join("\n")).toContain('"we""ird"');
    expect(awkward.join("\n")).not.toContain('"we"ird"');
  });

  it("refuses a role name that is absent or blank", () => {
    // Deny by default: a blank name would generate `grant ... to ""`, which is
    // a syntactically valid statement that grants to nothing.
    expect(() => servingRolePrivilegeStatements("")).toThrow(/role/i);
    expect(() => servingRolePrivilegeStatements("   ")).toThrow(/role/i);
  });
});
