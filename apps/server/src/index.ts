/**
 * Author: John Grimes
 */

import { serve } from "@hono/node-server";
import { createAuditRecorder, createDatabase } from "@signet/db";

import { createApp } from "./app.js";
import { bootstrapOptionsFrom, runBootstrapCommand } from "./bootstrap.js";
import {
  ConfigError,
  loadConfig,
  resolveDatabaseUrl,
  resolveMigrationIdentities,
} from "./config.js";
import { verifyEnforcement } from "./enforcement.js";
import { createRateLimitStore } from "./http/rateLimit.js";
import { runMigrateCommand } from "./migrate.js";

import type { AuditRecordFailure } from "@signet/db";

/** Reports a configuration problem the way an operator can act on. */
function reportConfigError(error: unknown): never {
  if (error instanceof ConfigError) {
    // Fail loudly and specifically rather than starting up half-configured.
    console.error(`Signet configuration error: ${error.message}`);
    process.exit(1);
  }
  throw error;
}

const command = process.argv[2];

// The commands are dispatched before the server's configuration is resolved, because
// each needs less than the server does: a migration uses a connection and nothing else,
// and demanding a public URL and a master key to run one would be an operator being told
// off by name for omitting something the command never reads.
if (command === "migrate") {
  try {
    // The only command that needs two identities: it applies DDL as the owner and
    // grants the serving role the access the server needs. It never uses the
    // serving password, so the migration job holds no credential it has no use
    // for.
    const identities = resolveMigrationIdentities(process.env);
    await runMigrateCommand(identities.ownerUrl, identities.servingRole);
  } catch (error) {
    if (error instanceof ConfigError) {
      reportConfigError(error);
    }
    console.error("Signet migration failed:", error);
    process.exit(1);
  }
  process.exit(0);
}

// `bootstrap` creates the first tenant and the first owner. Nothing in the console or
// the admin API can do that - both require a membership of a tenant that does not yet
// exist - and it is not a public route, because a deployment in front of clinical data
// should not accept a tenant from anybody who can reach the port.
if (command === "bootstrap") {
  try {
    await runBootstrapCommand(
      bootstrapOptionsFrom(process.env, resolveDatabaseUrl(process.env)),
    );
  } catch (error) {
    if (error instanceof ConfigError) {
      reportConfigError(error);
    }
    console.error(
      `Signet bootstrap failed: ${error instanceof Error ? error.message : String(error)}`,
    );
    process.exit(1);
  }
  process.exit(0);
}

let config;
try {
  config = loadConfig(process.env);
} catch (error) {
  reportConfigError(error);
}

const { db, close } = createDatabase({ url: config.databaseUrl });

// Before anything is served, and on the connection that will serve it: the policies
// constrain Signet only if the configured role is subject to them, and a deployment
// where it is not would run for months appearing correct. Reports the role it
// verified on success as well, so an operator can read the answer out of a log
// rather than having to ask the database.
try {
  await verifyEnforcement(db, config.logLevel);
} catch (error) {
  await close();
  if (error instanceof ConfigError) {
    reportConfigError(error);
  }
  // The check itself could not be performed - an unreachable database, most
  // likely. Refuse anyway: an unverified deployment is exactly the state this
  // exists to prevent serving in.
  console.error(
    `Signet could not verify tenant isolation enforcement: ${error instanceof Error ? error.message : String(error)}`,
  );
  process.exit(1);
}

/**
 * Reports an audit event that could not be written.
 *
 * Deliberately loud and structured. `@signet/db` accepts that an audit insert can
 * fail without failing the operation it describes - the alternative turns an audit
 * outage into an availability outage - which means this reporter is the *only*
 * signal that the trail has a gap. A deployment that needs a complete audit log
 * alerts on this message.
 */
function reportAuditFailure(failure: AuditRecordFailure): void {
  console.error(
    JSON.stringify({
      message: "signet.audit.write-failed",
      action: failure.action,
      tenantId: failure.tenantId,
      error: failure.error instanceof Error ? failure.error.message : "unknown",
    }),
  );
}

const app = createApp({
  config,
  db,
  audit: createAuditRecorder(reportAuditFailure),
  clock: () => new Date(),
  rateLimits: createRateLimitStore(),
});

const server = serve({ fetch: app.fetch, port: config.port }, (info) => {
  console.log(`Signet listening on http://localhost:${String(info.port)}`);
});

/**
 * Stops accepting connections, then releases the database pool.
 *
 * In that order: closing the pool first would fail every request already in flight,
 * including a token issuance that has consumed an authorization code and would then
 * have spent it for nothing.
 */
async function shutdown(signal: string): Promise<void> {
  console.log(`Signet shutting down on ${signal}`);
  await new Promise<void>((resolve) => {
    server.close(() => {
      resolve();
    });
  });
  await close();
  process.exit(0);
}

for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.on(signal, () => {
    void shutdown(signal);
  });
}
