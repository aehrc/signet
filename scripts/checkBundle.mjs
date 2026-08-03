// Fails when a bundle imports anything that is not a Node builtin.
//
// The runtime container ships no `node_modules`: the server is bundled into a
// single self-contained file. Anything left external at runtime would resolve to
// nothing and crash on startup, so this runs as a Docker build step — a
// dependency that cannot be bundled fails the build rather than the deployment.
//
// Bare builtin specifiers count as builtins. The Postgres driver imports `crypto`
// and `net` without the `node:` prefix, which is legitimate; an earlier version of
// this check only accepted the prefixed form and would have rejected them.
//
// Usage: node scripts/checkBundle.mjs <bundle.js> [...]

import { readFileSync } from "node:fs";
import { builtinModules } from "node:module";

const PATTERNS = [
  /\bfrom\s*["']([^"']+)["']/g,
  /\brequire\(\s*["']([^"']+)["']\s*\)/g,
  /\bimport\(\s*["']([^"']+)["']\s*\)/g,
];

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
      "\nproduction-install stage to deploy/docker/Dockerfile alongside it.",
  );
}

process.exit(failed ? 1 : 0);
