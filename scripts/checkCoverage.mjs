/**
 * Author: John Grimes
 */

// Fails when coverage over the whole suite falls below the floor.
//
// `bun test --coverage` has a `coverageThreshold` of its own, and it is not this
// gate: it is applied to every file separately, so a floor of 80% demands 80% of
// each of two hundred files rather than 80% of the code. Bun's "All files" row is
// not this gate either - it is the unweighted mean of the per-file percentages, in
// which a fully covered one-line module counts as much as a barely covered
// five-hundred-line one.
//
// So the totals are computed here, from the `LF`/`LH` and `FNF`/`FNH` records of
// the lcov report Bun writes, which are the found and hit counts per file. Summing
// them gives the same figure the previous runner reported and the same figure the
// quality gate in CLAUDE.md names.
//
// Branches are absent, and cannot be added here: Bun's coverage carries no branch
// data at all - no `BRF`/`BRH` records, no branch column - so there is nothing to
// total. The gate is lines and functions, and the constitution says so.
//
// Usage: node scripts/checkCoverage.mjs [lcov.info] [--floor 0.8]

import { readFileSync } from "node:fs";

/** The floor, as a fraction. Overridden by `--floor`. */
const DEFAULT_FLOOR = 0.8;

const args = process.argv.slice(2);
const floorIndex = args.indexOf("--floor");
const floor =
  floorIndex === -1 ? DEFAULT_FLOOR : Number(args[floorIndex + 1] ?? "");
const report =
  args.filter((argument) => !argument.startsWith("--"))[
    floorIndex === -1 ? 0 : 1
  ] ?? "coverage/lcov.info";

if (!Number.isFinite(floor) || floor <= 0 || floor > 1) {
  console.error(
    "usage: node scripts/checkCoverage.mjs [lcov.info] [--floor 0.8]",
  );
  process.exit(2);
}

/**
 * Totals the found and hit counts of one lcov record kind.
 *
 * @param source The lcov report.
 * @param found The record naming how many of the thing the file contains.
 * @param hit The record naming how many were reached.
 */
function total(source, found, hit) {
  let counted = 0;
  let reached = 0;
  for (const line of source.split("\n")) {
    if (line.startsWith(`${found}:`)) {
      counted += Number(line.slice(found.length + 1));
    } else if (line.startsWith(`${hit}:`)) {
      reached += Number(line.slice(hit.length + 1));
    }
  }
  return { counted, reached };
}

let source;
try {
  source = readFileSync(report, "utf8");
} catch {
  // Not a missing-file inconvenience: no report means the suite ran without
  // coverage, and reporting success on an absent measurement is the one outcome
  // this script exists to prevent.
  console.error(
    `${report} was not written. Run \`bun run test:coverage\`, which produces it.`,
  );
  process.exit(1);
}

const metrics = [
  { name: "Lines", ...total(source, "LF", "LH") },
  { name: "Functions", ...total(source, "FNF", "FNH") },
];

// Guards the guard. An empty report parses perfectly and divides to nothing, which
// would pass every floor below.
if (metrics.some((metric) => metric.counted === 0)) {
  console.error(`${report} records no coverage at all.`);
  process.exit(1);
}

let failed = false;
console.log(`Coverage over ${report}, floor ${(floor * 100).toFixed(0)}%:`);
for (const { name, counted, reached } of metrics) {
  const fraction = reached / counted;
  const below = fraction < floor;
  failed ||= below;
  console.log(
    `  ${name.padEnd(10)} ${(fraction * 100).toFixed(2)}% (${reached}/${counted})${
      below ? "  BELOW FLOOR" : ""
    }`,
  );
}

if (failed) {
  console.error(
    "\nThe floor is a floor, not a target. Cover the new code rather than lowering it.",
  );
}

process.exit(failed ? 1 : 0);
