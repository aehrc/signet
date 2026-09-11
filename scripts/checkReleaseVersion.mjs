/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Asserts the repository agrees with the version about to be published.
 *
 * A release publishes one image, `{repository}:{version}`, and the chart in this
 * repository is what an operator installs it with. If the chart still names the
 * previous version, `helm install` from a fresh checkout pulls an image that is
 * not the one just released - and nothing else in the build notices, because a
 * chart pinned to an older tag renders, lints and deploys perfectly.
 *
 * Run from the repository root, before anything is pushed:
 *
 *     node scripts/checkReleaseVersion.mjs 0.2.0 ghcr.io/aehrc/signet
 *
 * Author: John Grimes
 */

import { readFileSync } from "node:fs";

/** The chart's metadata, which carries the application version. */
const CHART = "deploy/helm/signet/Chart.yaml";

/** The chart's defaults, which carry the image an install runs. */
const VALUES = "deploy/helm/signet/values.yaml";

/** The chart's documentation, which repeats that default to the reader. */
const CHART_README = "deploy/helm/signet/README.md";

const [rawVersion, repository] = process.argv.slice(2);

if (!rawVersion || !repository) {
  console.error(
    "usage: node scripts/checkReleaseVersion.mjs <version> <image repository>",
  );
  process.exit(2);
}

// Releases are tagged `v0.2.0`; the image, the chart and the documentation all
// name the version without the prefix.
const version = rawVersion.replace(/^v/, "");
const image = `${repository}:${version}`;

if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
  console.error(`✗ ${rawVersion} is not a semantic version`);
  process.exit(1);
}

const failures = [];

/** Records a failure rather than throwing, so one run reports every problem. */
function check(condition, message) {
  if (!condition) {
    failures.push(message);
  }
}

/** The value of a top-level `appVersion`, quoted or not. */
function appVersionOf(chart) {
  return /^appVersion:\s*"?([^"\s]+)"?\s*$/m.exec(chart)?.[1];
}

/** The value of `signet.image`, which is the only image at that indent. */
function imageOf(values) {
  return /^ {2}image:\s*"([^"]+)"/m.exec(values)?.[1];
}

/** The default documented for `signet.image` in the chart's table. */
function documentedImageOf(readme) {
  return /\|\s*`signet\.image`\s*\|[^|]*\|\s*`([^`]+)`\s*\|/.exec(readme)?.[1];
}

const appVersion = appVersionOf(readFileSync(CHART, "utf8"));
const chartImage = imageOf(readFileSync(VALUES, "utf8"));
const documentedImage = documentedImageOf(readFileSync(CHART_README, "utf8"));

check(
  appVersion === version,
  `${CHART} declares appVersion ${String(appVersion)}, not ${version}`,
);
check(
  chartImage === image,
  `${VALUES} installs ${String(chartImage)}, not ${image}`,
);
check(
  documentedImage === image,
  `${CHART_README} documents the default image as ${String(documentedImage)}, not ${image}`,
);

if (failures.length > 0) {
  console.error(`✗ the repository does not agree with release ${rawVersion}:`);
  for (const failure of failures) {
    console.error(`  - ${failure}`);
  }
  console.error(
    "\nBump the chart in a commit on main and re-tag, rather than publishing an image the chart does not install.",
  );
  process.exit(1);
}

console.log(`✓ the chart installs ${image}, the image this release publishes`);
