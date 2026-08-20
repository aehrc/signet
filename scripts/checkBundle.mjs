/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

// Fails when a bundle imports anything that is not a Node builtin.
//
// The runtime container ships no `node_modules`: the server is bundled into a
// single self-contained file. Anything left external at runtime would resolve to
// nothing and crash on startup, so this runs as a Docker build step - a
// dependency that cannot be bundled fails the build rather than the deployment.
//
// Bare builtin specifiers count as builtins. The Postgres driver imports `crypto`
// and `net` without the `node:` prefix, which is legitimate; an earlier version of
// this check only accepted the prefixed form and would have rejected them.
//
// The patterns are lexical rather than a parse, so a bare `from "..."` anywhere in
// the bundled text would count - including inside the prose of an error message.
// That is not hypothetical: somewhere under `@simplewebauthn/server` is the message
// "Cannot get 'saltLength' from 'alg' argument", and reading that as an import of a
// module called `alg` fails the build for a dependency that bundles perfectly well.
// A false positive is the more dangerous of the two failures, because the obvious
// way to make the build pass again is to loosen the check.
//
// So the `from` clause is anchored on the `import` or `export` keyword that must
// precede it, with only the specifier list allowed in between - no quote, paren or
// semicolon, which is what separates a real clause from two unrelated words in a
// sentence. Every other form a bundler emits an external import in has a shape of
// its own and is matched directly. Candidates are then filtered to things that could
// be a module specifier at all, which is what keeps Drizzle's `sql`…from ${table``
// fragments out. `bundleCheck.test.ts` in `apps/server` asserts both directions.
//
// Usage: node scripts/checkBundle.mjs <bundle.js> [...]

import { readFileSync } from "node:fs";
import { builtinModules } from "node:module";

const PATTERNS = [
  // `import … from "x"`, `export … from "x"`, however the clause is wrapped.
  /\b(?:import|export)\b[^;'"`()]{0,200}?\bfrom\s*["']([^"'\n]+)["']/g,
  // `import "x"`, the side-effect-only form, which has no `from` at all. Anchored
  // to a statement boundary because the keyword and the quote are adjacent here,
  // and a sentence quoting the line to add - which `tsyringe` does, asking for a
  // `reflect-metadata` polyfill - would otherwise read as one.
  /(?:^|[;}\n])\s*import\s*["']([^"'\n]+)["']/gm,
  /\brequire\(\s*["']([^"'\n]+)["']\s*\)/g,
  /\bimport\(\s*["']([^"'\n]+)["']\s*\)/g,
];

/** What a module specifier can look like: a package name and an optional subpath. */
const SPECIFIER = /^(?:node:)?(?:@[\w.~-]+\/)?[\w.~-]+(?:\/[\w.~+-]+)*$/;

const builtins = new Set([
  ...builtinModules,
  ...builtinModules.map((name) => `node:${name}`),
]);

/** Returns the non-builtin bare specifiers a bundle still imports. */
function externalsOf(source) {
  const specifiers = new Set();
  for (const pattern of PATTERNS) {
    for (const [, specifier] of source.matchAll(pattern)) {
      specifiers.add(specifier);
    }
  }
  return [...specifiers]
    .filter(
      (specifier) => !specifier.startsWith(".") && !specifier.startsWith("/"),
    )
    .filter((specifier) => SPECIFIER.test(specifier))
    .filter((specifier) => !builtins.has(specifier))
    .toSorted();
}

const files = process.argv.slice(2);
if (files.length === 0) {
  console.error("usage: node scripts/checkBundle.mjs <bundle.js> [...]");
  process.exit(2);
}

let failed = false;
for (const file of files) {
  const externals = externalsOf(readFileSync(file, "utf8"));
  if (externals.length === 0) {
    console.log(`${file}: self-contained`);
    continue;
  }
  failed = true;
  console.error(`${file} is NOT self-contained. Non-builtin imports:`);
  for (const external of externals) {
    console.error(`  ${external}`);
  }
  console.error(
    "\nThe runtime image has no node_modules. Either make this dependency" +
      "\nbundlable (prefer WASM or pure JS over a native addon), or restore a" +
      "\nproduction-install stage to the Dockerfile alongside it.",
  );
}

process.exit(failed ? 1 : 0);
