/**
 * Proves the privileged routines are actually installed by a migration.
 *
 * The same claim `rls.migration.test.ts` makes about the policies, for the same
 * reason: a routine declared in `privileges.ts` that no migration creates is a
 * grant the `migrate` command would fail on, and a routine created without the
 * hardening below is a definer-privilege escalation waiting to be found.
 *
 * The properties asserted here are exactly the ones whose absence is invisible.
 * A `security definer` function with an unpinned `search_path` runs the caller's
 * schema resolution with the owner's privileges; one that is left executable by
 * `public` is reachable by every role in the deployment; and one whose parameter
 * shares a name with a column it compares against is a tautology that returns
 * every row. None of those changes what the routine returns in a passing test,
 * which is why they are read out of the SQL rather than inferred from behaviour.
 *
 * Author: John Grimes
 */

import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

import { resolveMigrationsFolder } from "./migrations.js";
import { PRIVILEGED_ROUTINES } from "./privileges.js";

/** The migration folder the `migrate` command would apply. */
const folder = resolveMigrationsFolder();

/** Every generated migration, newest last, as one searchable body of SQL. */
const migrationSql = readdirSync(folder)
  .filter((name) => name.endsWith(".sql"))
  .toSorted()
  .map((name) => readFileSync(path.join(folder, name), "utf8"))
  .join("\n")
  .toLowerCase();

/** The journal the migrator reads to decide what to run. */
const journal = JSON.parse(
  readFileSync(path.join(folder, "meta", "_journal.json"), "utf8"),
) as { readonly entries: readonly { readonly tag: string }[] };

/** The declared routines, by bare name and by full signature. */
const routines = Object.keys(PRIVILEGED_ROUTINES).map((signature) => ({
  signature,
  name: signature.slice(0, signature.indexOf("(")),
}));

/**
 * The body of a `create ... function <name>` statement, up to its terminator.
 *
 * Sliced from the whole folder rather than from one named file, because which
 * migration creates a routine is not the property under test - that it is
 * created, and created safely, is.
 */
function definitionOf(name: string): string {
  const start = migrationSql.indexOf(`function ${name}(`);
  expect(start, `no create function for ${name}`).toBeGreaterThanOrEqual(0);
  const rest = migrationSql.slice(start);
  const end = rest.indexOf("$$;");
  expect(end, `unterminated definition for ${name}`).toBeGreaterThan(0);
  return rest.slice(0, end);
}

describe("the privileged routines are installed by migration", () => {
  it("guards the guard", () => {
    // If the folder resolved somewhere empty, or the declaration were empty,
    // every assertion below would pass against nothing.
    expect(migrationSql.length).toBeGreaterThan(1000);
    expect(routines.length).toBeGreaterThan(0);
  });

  it.each(routines)("creates $name", ({ name }) => {
    expect(migrationSql).toContain(`function ${name}(`);
  });

  it.each(routines)("declares $name security definer", ({ name }) => {
    // Without this the routine runs as the caller, which is the serving role,
    // which the policies bind - so the resolution it exists to perform returns
    // nothing and every request 404s.
    expect(definitionOf(name)).toContain("security definer");
  });

  it.each(routines)("pins the search path on $name", ({ name }) => {
    // The one that matters most. A definer routine with an unpinned search path
    // resolves its own table references against whatever schema the caller put
    // first, with the owner's privileges - which is the textbook escalation.
    expect(definitionOf(name)).toContain("set search_path");
  });

  it.each(routines)(
    "revokes execute on $signature from public",
    ({ signature }) => {
      expect(migrationSql).toContain(`on function ${signature} from public`);
    },
  );

  it.each(routines)("prefixes every parameter of $name", ({ name }) => {
    // In a `language sql` function a parameter whose name matches a column is
    // resolved in favour of the column, so `where slug = slug` is a tautology
    // that matches every row. The prefix is what makes that impossible, and this
    // is the only place it can be checked - the mistake produces a routine that
    // works perfectly for the single-tenant case every other test exercises.
    const signature = definitionOf(name).slice(
      definitionOf(name).indexOf("("),
      definitionOf(name).indexOf(")"),
    );
    const parameters = signature
      .replace("(", "")
      .split(",")
      .map((parameter) => parameter.trim())
      .filter((parameter) => parameter.length > 0);

    expect(parameters.length).toBeGreaterThan(0);
    for (const parameter of parameters) {
      expect(parameter, `${name} parameter "${parameter}"`).toMatch(/^p_/);
    }
  });

  it("journals the migration that creates them", () => {
    // A SQL file that is not in the journal is never applied. It would sit in
    // the repository looking like a routine that exists, and the grants the
    // `migrate` command issues for it would fail.
    const tags = new Set(journal.entries.map((entry) => entry.tag));
    const creating = readdirSync(folder)
      .filter((name) => name.endsWith(".sql"))
      .filter((name) =>
        routines.some(({ name: routine }) =>
          readFileSync(path.join(folder, name), "utf8")
            .toLowerCase()
            .includes(`function ${routine}(`),
        ),
      )
      .map((name) => name.replace(/\.sql$/, ""));

    expect(creating.length).toBeGreaterThan(0);
    for (const tag of creating) {
      expect(tags.has(tag), `${tag} is not journalled`).toBe(true);
    }
  });
});
