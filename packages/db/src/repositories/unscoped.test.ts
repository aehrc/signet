/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  SWEEP_FUNCTIONS,
  UNSCOPED_FUNCTIONS,
  UNSCOPED_MODULES,
} from "./unscoped.js";

/** `packages/db/src`, which every declared key is relative to. */
const sourceRoot = fileURLToPath(new URL("..", import.meta.url));

/** An exported function, and whether it can reach the database unbound. */
interface Signature {
  /** `<module path without extension>.<function name>`, as declared. */
  readonly key: string;
  readonly module: string;
  readonly unbound: boolean;
}

/**
 * Every exported function of a module, with its parameter list.
 *
 * Parentheses are balanced rather than matched with a regular expression, because
 * a parameter can itself be a function type - and a scan that stopped at the first
 * closing bracket would read half a signature and reach the wrong conclusion about
 * it. The parameter list is found by scanning forward from the name rather than
 * required to follow it immediately, so a generic function is not skipped: missing
 * one would let it reach the database unbound without being declared.
 */
function signaturesOf(module: string, source: string): readonly Signature[] {
  const found: Signature[] = [];
  const declaration = /export (?:async )?function (\w+)/g;

  let match = declaration.exec(source);
  while (match !== null) {
    const name = match[1] ?? "";
    const open = source.indexOf("(", match.index + match[0].length);
    let depth = 1;
    let index = open + 1;
    while (index < source.length && depth > 0) {
      const character = source[index];
      if (character === "(") {
        depth += 1;
      } else if (character === ")") {
        depth -= 1;
      }
      index += 1;
    }

    const parameters = source.slice(open + 1, index - 1);
    found.push({
      key: `${module}.${name}`,
      module,
      unbound: /\bExecutor\b/.test(parameters),
    });
    match = declaration.exec(source);
  }

  return found;
}

/** Every module under `packages/db/src` that this declaration governs. */
function scannedModules(): readonly string[] {
  const directories = ["repositories", "audit"];
  return directories.flatMap((directory) =>
    readdirSync(new URL(`${directory}/`, new URL("..", import.meta.url)))
      .filter((entry) => entry.endsWith(".ts") && !entry.includes(".test."))
      .filter((entry) => entry !== "index.ts")
      .map((entry) => `${directory}/${entry.replace(/\.ts$/, "")}`),
  );
}

const signatures = scannedModules().flatMap((module) =>
  signaturesOf(module, readFileSync(`${sourceRoot}${module}.ts`, "utf8")),
);

/** Functions that can reach the database with no tenant declared. */
const unbound = signatures.filter((signature) => signature.unbound);

/** Whether a module's unbound functions are covered wholesale. */
function moduleIsExempt(module: string): boolean {
  return Object.hasOwn(UNSCOPED_MODULES, module);
}

/** Whether one function is accounted for by name. */
function isDeclared(signature: Signature): boolean {
  return (
    Object.hasOwn(UNSCOPED_FUNCTIONS, signature.key) ||
    SWEEP_FUNCTIONS.includes(signature.key)
  );
}

describe("the declared unscoped surface", () => {
  it("finds the source it is meant to be checking", () => {
    // Guards the guard: a scan that returned nothing would make every assertion
    // below pass while asserting nothing at all.
    expect(scannedModules().length).toBeGreaterThan(20);
    expect(signatures.length).toBeGreaterThan(100);
    expect(unbound.length).toBeGreaterThan(0);
  });

  it("accounts for every function that can reach the database unbound", () => {
    const unaccounted = unbound
      .filter(
        (signature) =>
          !isDeclared(signature) && !moduleIsExempt(signature.module),
      )
      .map((signature) => signature.key);

    // A new function taking an `Executor` is a new way to reach tenant-owned data
    // with no tenant declared. It must be justified here, or take a bound scope.
    expect(unaccounted).toEqual([]);
  });

  it("declares nothing that is not in the source", () => {
    const keys = new Set(unbound.map((signature) => signature.key));
    const stale = [
      ...Object.keys(UNSCOPED_FUNCTIONS),
      ...SWEEP_FUNCTIONS,
    ].filter((key) => !keys.has(key));

    // A declaration for a function that has been renamed, deleted or converted is
    // a justification for something nobody can read any more.
    expect(stale).toEqual([]);
  });

  it("names every table the sweep touches", () => {
    // The sweep's counts and its declared statements are the same list. A delete
    // added to the sweep without being declared here reaches tenant-owned data
    // with no tenant and nothing would have said so.
    const swept = readFileSync(`${sourceRoot}repositories/sweep.ts`, "utf8");
    const called = SWEEP_FUNCTIONS.map((key) => key.split(".", 2)[1] ?? "");

    expect(called).not.toContain("");
    for (const name of called) {
      expect(swept).toContain(name);
    }
    expect(
      [...swept.matchAll(/\bdeleteExpired\w+/g)].map((match) => match[0]),
    ).toEqual(expect.arrayContaining(called));
  });

  it("declares no module that has no unbound function", () => {
    const modules = new Set(unbound.map((signature) => signature.module));
    expect(
      Object.keys(UNSCOPED_MODULES).filter((module) => !modules.has(module)),
    ).toEqual([]);
  });

  it("gives a reason for every entry", () => {
    for (const reason of [
      ...Object.values(UNSCOPED_MODULES),
      ...Object.values(UNSCOPED_FUNCTIONS),
    ]) {
      expect(reason.length).toBeGreaterThan(40);
    }
  });
});
