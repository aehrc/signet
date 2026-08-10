/**
 * Asserts the rendered chart keeps the two database identities apart.
 *
 * Signet connects as a role the tenant isolation policies bind, and the identity
 * that owns the schema is exempt from them. Keeping those apart is the whole
 * feature, and in a Kubernetes deployment it comes down to which pod spec carries
 * which credential: the migration Job needs the owning identity because migrations
 * are DDL, the sweep CronJob needs it because it acts across tenants, and the
 * server must not have it, because a server holding it could reach any tenant's
 * rows regardless of what the code does.
 *
 * That is a property of rendered YAML, so it is checked by rendering. A template
 * that leaks the owner credential into the Deployment renders perfectly well and
 * lints clean; the only thing that catches it is reading the output.
 *
 * Run as `bun run check:chart`, and in CI beside `helm lint`. Requires `helm` on
 * the path and fails loudly without it rather than reporting success - a check
 * that skips itself is the failure mode the fourth principle exists to prevent.
 *
 * Author: John Grimes
 */

import { execFileSync } from "node:child_process";

/** The chart, relative to the repository root. */
const CHART = "deploy/helm/signet";

/** The variable naming the owning identity. */
const OWNER_VARIABLE = "SIGNET_DATABASE_OWNER_URL";

/**
 * Secret keys that would give a pod the owning identity.
 *
 * `ownerPassword` is the bundled PostgreSQL's superuser, which is the owning
 * identity when that database is enabled. `ownerUrl` is the key of the secret the
 * chart creates for an external database. Either present in the Job's spec, and
 * either appearing in the server's would hand the server owner authority by
 * another name - which is why the check looks for the keys and not only for the
 * variable.
 */
const OWNER_SECRET_KEYS = ["ownerPassword", "ownerUrl"];

/**
 * The configurations to render.
 *
 * Both database paths, because they compose the two identities differently: the
 * bundled PostgreSQL creates a superuser and a non-owning role, and an external
 * database has whatever two roles the operator supplied.
 */
const CONFIGURATIONS = [
  { name: "bundled PostgreSQL", flags: [] },
  {
    name: "external database with existing secrets",
    flags: [
      "--set",
      "signet.postgres.enabled=false",
      "--set",
      "signet.database.existingSecret=external-db",
      "--set",
      "signet.database.ownerExistingSecret=external-db-owner",
      "--set",
      "signet.masterKey.existingSecret=external-key",
    ],
  },
  {
    // A separate branch of the templates, not a variation on the one above: here
    // the chart creates both secrets itself, so it is the chart rather than the
    // operator that decides which pod spec each is mounted into.
    name: "external database with chart-created secrets",
    flags: [
      "--set",
      "signet.postgres.enabled=false",
      "--set",
      "signet.database.url=postgres://app:pw@db:5432/signet",
      "--set",
      "signet.database.ownerUrl=postgres://owner:pw@db:5432/signet",
      "--set",
      "signet.masterKey.existingSecret=external-key",
    ],
  },
];

/** Renders the chart, returning its manifests split into documents. */
function render(flags) {
  const output = execFileSync("helm", ["template", "signet", CHART, ...flags], {
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
  });

  return output
    .split(/^---$/m)
    .map((document) => document.trim())
    .filter((document) => document.length > 0);
}

/** A manifest's `kind`, or undefined when it declares none. */
function kindOf(document) {
  return /^kind:\s*(\S+)/m.exec(document)?.[1];
}

/** A manifest's `metadata.name`. */
function nameOf(document) {
  return /^metadata:\s*\n(?:\s+.*\n)*?\s+name:\s*(\S+)/m.exec(document)?.[1];
}

const failures = [];

/** Records a failure rather than throwing, so one run reports every problem. */
function check(condition, message) {
  if (!condition) {
    failures.push(message);
  }
}

for (const { name, flags } of CONFIGURATIONS) {
  const documents = render(flags);

  const deployments = documents.filter(
    (document) => kindOf(document) === "Deployment",
  );
  const migrationJobs = documents.filter(
    (document) =>
      kindOf(document) === "Job" &&
      (nameOf(document) ?? "").endsWith("-migrate"),
  );

  // Guards the guard. A render that produced neither would let every assertion
  // below pass while asserting nothing at all.
  check(
    deployments.length === 1,
    `${name}: expected exactly one Deployment, found ${String(deployments.length)}`,
  );
  check(
    migrationJobs.length === 1,
    `${name}: expected exactly one migration Job, found ${String(migrationJobs.length)}`,
  );

  // The expiry sweep is the second path that needs the owning identity: it acts
  // across tenants, which the serving role cannot do. The command refuses a
  // connection the policies bind, so a CronJob given the wrong credential fails
  // rather than reporting a clean database - but a CronJob given no credential at
  // all is a chart bug, and this is what catches it.
  const sweepJobs = documents.filter(
    (document) =>
      kindOf(document) === "CronJob" &&
      (nameOf(document) ?? "").endsWith("-sweep"),
  );

  check(
    sweepJobs.length === 1,
    `${name}: expected exactly one sweep CronJob, found ${String(sweepJobs.length)}`,
  );

  for (const document of [...migrationJobs, ...sweepJobs]) {
    check(
      document.includes(OWNER_VARIABLE),
      `${name}: ${nameOf(document) ?? "a job"} does not carry ${OWNER_VARIABLE}, so it cannot act as the identity it needs`,
    );
  }

  for (const document of deployments) {
    check(
      !document.includes(OWNER_VARIABLE),
      `${name}: the server's Deployment carries ${OWNER_VARIABLE}. A server holding the owning identity is exempt from the tenant isolation policies`,
    );
    for (const key of OWNER_SECRET_KEYS) {
      check(
        !document.includes(key),
        `${name}: the server's Deployment references the secret key "${key}", which is the owning identity under another name`,
      );
    }
  }
}

if (failures.length > 0) {
  for (const failure of failures) {
    console.error(`✗ ${failure}`);
  }
  process.exit(1);
}

console.log(
  `✓ ${String(CONFIGURATIONS.length)} chart configurations keep the owning identity to the migration Job and the sweep CronJob`,
);
