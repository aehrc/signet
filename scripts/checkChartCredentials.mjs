/**
 * Asserts the rendered chart keeps the two database identities apart.
 *
 * Signet connects as a role the tenant isolation policies bind, and the identity
 * that owns the schema is exempt from them. Keeping those apart is the whole
 * feature, and in a Kubernetes deployment it comes down to which pod spec carries
 * which credential: the migration Job needs the owning identity because migrations
 * are DDL, and the server must not have it, because a server holding it could
 * reach any tenant's rows regardless of what the code does.
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
 * `postgres-password` is the bundled subchart's superuser, which is the owning
 * identity when the subchart is enabled. Present in the Job's spec, and its
 * appearance in the server's would hand the server owner authority by another
 * name - which is why the check looks for the key and not only for the variable.
 */
const OWNER_SECRET_KEYS = ["postgres-password"];

/**
 * The configurations to render.
 *
 * Both database paths, because they compose the two identities differently: the
 * bundled subchart already has a superuser and a non-owning user, and an external
 * database has whatever two roles the operator supplied.
 */
const CONFIGURATIONS = [
  { name: "bundled PostgreSQL subchart", flags: [] },
  {
    name: "external database with existing secrets",
    flags: [
      "--set",
      "postgresql.enabled=false",
      "--set",
      "database.existingSecret=external-db",
      "--set",
      "database.ownerExistingSecret=external-db-owner",
      "--set",
      "masterKey.existingSecret=external-key",
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

  for (const document of migrationJobs) {
    check(
      document.includes(OWNER_VARIABLE),
      `${name}: the migration Job does not carry ${OWNER_VARIABLE}, so it cannot apply migrations or grant the serving role`,
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
  `✓ ${String(CONFIGURATIONS.length)} chart configurations keep the owning identity to the migration Job`,
);
