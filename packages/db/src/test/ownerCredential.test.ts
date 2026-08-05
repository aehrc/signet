/**
 * Where the owning identity may be reached from, and nowhere else.
 *
 * The suite is only evidence that the policies bind Signet if the suite runs
 * under them. Once it did not: every connection was made as the identity that
 * owns the tables, which Postgres exempts, so the policies could have been
 * dropped entirely and 3,000 tests would have passed.
 *
 * That is now fixed, and this is what stops it coming back. Observing every
 * connection at runtime is not practical - a suite that skipped itself would
 * observe nothing, and one that passed would prove only that the connections it
 * happened to make were the right ones. Asserting *which files can act as the
 * owning identity* is practical, and it is the property that matters: a file that
 * cannot reach the credential cannot connect as it.
 *
 * A file can reach it two ways, and the second is the one a list keyed on the
 * variable's name would miss: reading it from the environment, or opening a
 * connection from a URL that was not derived through `servingRoleUrl` - which is
 * how a suite importing the harness's `testDatabaseUrl` reaches it without the
 * variable appearing anywhere in the file. Both count, and the declared list below
 * is compared against both in the two directions the pattern in
 * `../repositories/unscoped.ts` uses: nothing undeclared reaches it, and nothing
 * declared has stopped reaching it.
 *
 * Then the positive: no other suite opens a connection at all - they all come
 * through the harness - and the harness derives that connection from the serving
 * role. Those two together are what make ninety-odd files evidence rather than
 * decoration.
 *
 * The declaration lives in this file rather than in a source module, unlike
 * `unscoped.ts`, because every entry is a test file: a list of suites belongs
 * beside the assertion about suites, not in the package's published surface.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** The variable naming the owning identity. */
const OWNER_VARIABLE = "SIGNET_TEST_DATABASE_URL";

/** The repository root, from this file's location within it. */
const repositoryRoot = fileURLToPath(new URL("../../../..", import.meta.url));

/** The trees whose connections this governs. */
const scanned = ["packages/db/src", "apps/server/src"];

/**
 * Files permitted to reach the owning identity, and why.
 *
 * Keyed by path from the repository root, and used by both assertions: this is the
 * set that may read the credential *and* the set that may open a connection which
 * is not derived through `servingRoleUrl`. One list, because they are one question -
 * which files can act as the identity the policies exempt.
 *
 * Every entry is either schema setup, the expiry sweep's own tests, or a suite
 * whose subject is the distinction between the two identities. There is no fourth
 * kind, which is the point of enumerating them.
 */
const OWNER_IDENTITY_FILES: Readonly<Record<string, string>> = {
  "packages/db/src/test/preload.ts":
    "Migrates and creates the serving role once, before the first test file is imported. The only place in the suite that performs DDL, and it closes the connection before any test runs.",
  "packages/db/src/repositories/repositories.integration.test.ts":
    "Holds the expiry sweep's own tests. The sweep is cross-tenant by design and requires the owning identity, so this suite must connect as it explicitly - and asserts the converse, that the same sweep attempted as the serving role deletes nothing. Every other connection it makes is the serving role.",
  "packages/db/src/rls.enforcement.integration.test.ts":
    "Seeds two tenants' fixtures as the owning identity, so that seeding is not part of the property being asserted, and observes the owning identity being refused by the startup check - which is the credential a deployment must not give the server.",
  "packages/db/src/privileges.integration.test.ts":
    "Seeds fixtures and reads the privilege catalogues as the owning identity. The routines it then calls, and the surface it asserts, are the serving role's.",
  "packages/db/src/audit/record.integration.test.ts":
    "Seeds a tenant as the owning identity, then asserts the audit write binds its own transaction as the serving role.",
  "apps/server/src/test/harness.ts":
    "Migrates as a fallback for a file run outside the global setup, closing the owning connection before returning, and derives every stack's serving connection from the same URL.",
  "apps/server/src/enforcement.integration.test.ts":
    "The startup check's own suite. It must connect as four identities - owning, exempt, under-privileged and correct - because which of them is refused is the behaviour under test.",
  "apps/server/src/migrate.integration.test.ts":
    "Runs the `migrate` command, which requires the owning identity by design, and then observes the privileges it left in force for a serving role it names rather than connects as.",
};

/** Every `.ts` file under the scanned trees, by repository-relative path. */
function sourceFiles(): readonly string[] {
  const found: string[] = [];

  const walk = (relative: string): void => {
    for (const entry of readdirSync(path.join(repositoryRoot, relative))) {
      const next = `${relative}/${entry}`;
      if (statSync(path.join(repositoryRoot, next)).isDirectory()) {
        walk(next);
      } else if (entry.endsWith(".ts")) {
        found.push(next);
      }
    }
  };

  for (const tree of scanned) {
    walk(tree);
  }
  return found;
}

const files = sourceFiles();

/**
 * The suite's own files: the test files and the helpers they build on.
 *
 * The connection assertion is scoped to these, because the property is about what
 * the suite connects as. A production module takes its URL from configuration
 * rather than choosing one, and which role that names is the subject of the
 * startup check in `../enforcement.ts`, not of a source scan.
 */
const suiteFiles = files.filter(
  (file) => file.includes(".test.") || file.includes("/test/"),
);

/**
 * A file with its comments removed.
 *
 * Necessary, not tidiness: several modules here document how to open a connection,
 * in an `@example` that shows the very call this scan looks for. Counting prose as
 * code makes a file that only *describes* a connection look like one that opens
 * one - and this file, which describes both, was the first to do it.
 */
function withoutComments(source: string): string {
  return source
    .replaceAll(/\/\*[\s\S]*?\*\//g, "")
    .replaceAll(/^\s*\/\/.*$/gm, "");
}

/** Each file's code, read once and stripped of its documentation. */
const contentsOf = new Map(
  files.map((file) => [
    file,
    withoutComments(readFileSync(path.join(repositoryRoot, file), "utf8")),
  ]),
);

/**
 * Reading the variable, as opposed to mentioning its name.
 *
 * Several modules name it in documentation or in the error they raise for a URL
 * they cannot parse, which is the opposite of a problem - it is how a developer is
 * told which variable to fix without being shown a string containing a password.
 * What matters is who reads the value.
 */
const read = new RegExp(
  String.raw`process\.env(?:\.${OWNER_VARIABLE}|\[\s*"${OWNER_VARIABLE}"\s*\])`,
);

/** Files that read the owning credential out of the environment. */
const readers = files.filter((file) => read.test(contentsOf.get(file) ?? ""));

/**
 * Every connection a file opens, as the expression naming its URL.
 *
 * Both constructors are matched: `createDatabase({ url: ... })` is the package's
 * own, and `postgres(...)` is the driver underneath it, which the integration
 * suites use directly when they need two connections with different pool sizes.
 * A suite reaching past both to some third mechanism is not something to guess at
 * - the reachability assertion in `../rls.enforcement.integration.test.ts` is what
 * would catch a connection this scan missed, since a suite connecting as the
 * owning identity would see other tenants' rows.
 */
function connectionsIn(source: string): readonly string[] {
  const found: string[] = [];
  const opening = /(?:createDatabase\(\{\s*url:|postgres\()\s*/g;

  let match = opening.exec(source);
  while (match !== null) {
    const from = match.index + match[0].length;
    // Up to the argument's terminator: a comma at depth zero, or the closing
    // bracket. `servingRoleUrl(url)` contains a bracket pair of its own, so the
    // scan has to balance rather than stop at the first one.
    let depth = 0;
    let index = from;
    while (index < source.length) {
      const character = source[index];
      if (character === "(" || character === "{") {
        depth += 1;
      } else if (character === ")" || character === "}") {
        if (depth === 0) {
          break;
        }
        depth -= 1;
      } else if (character === "," && depth === 0) {
        break;
      }
      index += 1;
    }

    found.push(source.slice(from, index).trim());
    match = opening.exec(source);
  }

  return found;
}

/** Whether an expression derives its URL through the serving role. */
function isServingConnection(expression: string): boolean {
  return expression.includes("servingRoleUrl(");
}

/**
 * Connections a file opens that are not the serving role's.
 *
 * A helper taking its URL as a parameter chooses no role - its caller does, and
 * the caller is a file this scan covers - so a bare `url` argument is not a
 * finding.
 */
function ownerConnectionsIn(file: string): readonly string[] {
  return connectionsIn(contentsOf.get(file) ?? "")
    .filter((expression) => !isServingConnection(expression))
    .filter((expression) => !/^url,?$/.test(expression));
}

/**
 * Whether a file can act as the identity the policies exempt.
 *
 * Either of two routes counts, and the second is the one a declared list keyed on
 * the variable's name would miss: reading the credential from the environment, or
 * opening a connection from a URL that was not derived through `servingRoleUrl` -
 * which is how a suite importing the harness's `testDatabaseUrl` reaches it
 * without the variable appearing anywhere in the file.
 */
function reachesOwningIdentity(file: string): boolean {
  return (
    readers.includes(file) ||
    (suiteFiles.includes(file) && ownerConnectionsIn(file).length > 0)
  );
}

describe("the owning credential", () => {
  it("finds the source it is meant to be checking", () => {
    // Guards the guard. A scan that resolved somewhere empty would make every
    // assertion below pass while asserting nothing.
    expect(files.length).toBeGreaterThan(100);
    expect(suiteFiles.length).toBeGreaterThan(50);
    expect(readers.length).toBeGreaterThan(5);
    expect(
      suiteFiles.filter(
        (file) => connectionsIn(contentsOf.get(file) ?? "").length > 0,
      ).length,
    ).toBeGreaterThan(5);
  });

  it("is reachable only where the declaration allows", () => {
    const undeclared = files
      .filter((file) => reachesOwningIdentity(file))
      .filter((file) => !Object.hasOwn(OWNER_IDENTITY_FILES, file));

    // A suite that can act as the owning identity is exempt from the policies, and
    // a suite that is exempt from them is not evidence of anything. Either derive
    // the connection through `servingRoleUrl`, or declare why the owning identity
    // is needed and what is done with it.
    expect(undeclared).toEqual([]);
  });

  it("declares nothing that no longer reaches it", () => {
    const stale = Object.keys(OWNER_IDENTITY_FILES).filter(
      (file) => !reachesOwningIdentity(file),
    );

    // A justification for a file that has been renamed, deleted or converted to the
    // serving role is a reason nobody can check any more - and it would go on
    // exempting that path from the assertion above.
    expect(stale).toEqual([]);
  });

  it.each(Object.entries(OWNER_IDENTITY_FILES))(
    "gives a reason for %s",
    (_file, reason) => {
      // An entry is an exemption from the assertions above, so it has to say what
      // the owning identity is for. A bare path is not a justification.
      expect(reason.length).toBeGreaterThan(40);
    },
  );

  it("has one origin for every other suite's connection", () => {
    // Stated as the positive. Every suite not declared above reaches the database
    // through the harness and opens nothing itself, so there is no second origin
    // the declaration could have missed. The guard above is what proves this scan
    // sees suites at all; the emptiness here is the property.
    const opening = suiteFiles
      .filter((file) => !Object.hasOwn(OWNER_IDENTITY_FILES, file))
      .filter((file) => connectionsIn(contentsOf.get(file) ?? "").length > 0);

    expect(opening).toEqual([]);
  });

  it("derives that origin's connection from the serving role", () => {
    // And the origin itself. The harness is where every server suite's stack comes
    // from, so this one line is what makes 90-odd files evidence rather than
    // decoration: pointed at the owning identity instead, every one of them would
    // pass with the policies dropped.
    const harness = contentsOf.get("apps/server/src/test/harness.ts") ?? "";
    const opened = connectionsIn(harness);

    // Its only non-serving connection is the migration fallback, which the module
    // closes before returning. Named by the expression rather than counted, so a
    // second owning connection added anywhere in the file fails this.
    expect(
      opened.filter((expression) => !isServingConnection(expression)),
    ).toEqual(["ownerUrl"]);
    expect(opened.filter(isServingConnection).length).toBeGreaterThan(0);
  });
});
