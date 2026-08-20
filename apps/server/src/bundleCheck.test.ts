/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * What the self-contained-bundle gate accepts and refuses.
 *
 * `scripts/checkBundle.mjs` is what stands between a dependency that cannot be
 * bundled and a deployment that crashes on startup, and it decides by scanning the
 * bundled text rather than by parsing it. That is the right trade for a build step -
 * a parser for whatever a bundler emitted is a much larger thing to maintain - but
 * it means the gate has two ways to be wrong, and only one of them is visible.
 *
 * A missed import ships a broken image. A false positive is worse in a subtler way:
 * it fails a build for a dependency that is perfectly bundlable, and the fix that
 * suggests itself is to loosen the check until it passes. `@simplewebauthn/server`
 * is exactly that case - somewhere in its dependency tree is the message "Cannot get
 * 'saltLength' from 'alg' argument", and a scan for `from "…"` reads `from 'alg'` as
 * an unbundled module named `alg`.
 *
 * So both directions are asserted here: every form a bundler emits an external
 * import in is caught, and prose that merely contains the word `from` is not. The
 * script is run as a subprocess, the way the Dockerfile runs it, so what is under
 * test is the artefact rather than a copy of its patterns.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** The script the Docker build runs against the server bundle. */
const script = fileURLToPath(
  new URL("../../../scripts/checkBundle.mjs", import.meta.url),
);

/**
 * Runs the gate over one file of bundled text.
 *
 * @param source - What the bundle would contain.
 * @returns The exit code, and what the script said.
 */
async function check(
  source: string,
): Promise<{ readonly code: number; readonly output: string }> {
  const directory = mkdtempSync(path.join(tmpdir(), "signet-bundle-"));
  const file = path.join(directory, "bundle.js");
  writeFileSync(file, source, "utf8");

  const run = Bun.spawn(["node", script, file], {
    stdout: "pipe",
    stderr: "pipe",
  });
  const output = `${await new Response(run.stdout).text()}${await new Response(run.stderr).text()}`;
  return { code: await run.exited, output };
}

describe("the self-contained bundle gate", () => {
  // Every shape a bundler leaves behind when it does not inline a dependency. A
  // gate that missed any one of them would pass an image that cannot start.
  it.each([
    ["a named import", 'import { thing } from "left-pad";'],
    ["a default import", 'import thing from "left-pad";'],
    ["a namespace import", 'import * as thing from "left-pad";'],
    ["a bare import", 'import "left-pad";'],
    ["a re-export", 'export { thing } from "left-pad";'],
    ["a require", 'const thing = require("left-pad");'],
    ["a dynamic import", 'const thing = await import("left-pad");'],
  ])("refuses %s of a package that was left external", async (_name, line) => {
    const { code, output } = await check(line);

    expect(code).toBe(1);
    expect(output).toContain("left-pad");
    expect(output).toContain("NOT self-contained");
  });

  it("accepts a bundle that imports only Node builtins", async () => {
    // Both spellings: the Postgres driver imports `crypto` without the prefix,
    // which is legitimate and was once refused.
    const { code, output } = await check(
      [
        'import { readFileSync } from "node:fs";',
        'const net = require("net");',
      ].join("\n"),
    );

    expect(code).toBe(0);
    expect(output).toContain("self-contained");
  });

  it("accepts prose that happens to contain the word from", async () => {
    // The `@simplewebauthn/server` case, verbatim. A gate that reads this as an
    // import fails the build for a dependency that bundles perfectly well.
    const { code, output } = await check(
      `throw new Error("Cannot get 'saltLength' from 'alg' argument");`,
    );

    expect(code).toBe(0);
    expect(output).toContain("self-contained");
  });

  it("accepts prose that quotes an import statement", async () => {
    // `tsyringe`, reached through the same dependency tree, asks for a polyfill by
    // quoting the line the reader should add. The module it names is bundled; the
    // sentence mentioning it is not an import of anything.
    const { code, output } = await check(
      "throw new Error(`tsyringe requires a reflect polyfill. Please add 'import \"reflect-metadata\"' to the top of your entry point.`);",
    );

    expect(code).toBe(0);
    expect(output).toContain("self-contained");
  });

  it("accepts a SQL fragment that selects from a table", async () => {
    // Drizzle's query builder is full of these, and they are the false positives
    // the specifier filter was originally added for.
    const { code } = await check(`const q = sql('select 1 from "tenants"');`);

    expect(code).toBe(0);
  });
});
