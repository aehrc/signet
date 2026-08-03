import { serve } from "@hono/node-server";
import { createAuditRecorder, createDatabase } from "@signet/db";

import { createApp } from "./app.js";
import { ConfigError, loadConfig } from "./config.js";
import { runMigrateCommand } from "./migrate.js";

import type { AuditRecordFailure } from "@signet/db";

let config;
try {
  config = loadConfig(process.env);
} catch (error) {
  if (error instanceof ConfigError) {
    // Fail loudly and specifically rather than starting up half-configured.
    console.error(`Signet configuration error: ${error.message}`);
    process.exit(1);
  }
  throw error;
}

// `migrate` is a separate command, invoked by the chart's pre-upgrade hook Job. It
// deliberately does not run as part of startup: several replicas racing to apply the
// same migration is how a half-migrated schema happens.
if (process.argv[2] === "migrate") {
  try {
    await runMigrateCommand(config.databaseUrl);
  } catch (error) {
    console.error("Signet migration failed:", error);
    process.exit(1);
  }
  process.exit(0);
}

const { db, close } = createDatabase({ url: config.databaseUrl });

/**
 * Reports an audit event that could not be written.
 *
 * Deliberately loud and structured. `@signet/db` accepts that an audit insert can
 * fail without failing the operation it describes — the alternative turns an audit
 * outage into an availability outage — which means this reporter is the *only*
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
