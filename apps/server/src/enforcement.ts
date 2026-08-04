/**
 * Refusing to serve when the database would not constrain us.
 *
 * The tenant isolation policies bind a connection only if the role it was made by
 * is subject to them, and which role that is is configuration. So a deployment can
 * be wrong in a way no code review catches and no request fails on: the server
 * works, the policies are installed, and every query reaches every tenant's rows.
 *
 * This is where that is caught. `@signet/db` observes the database and decides what
 * the observations mean - both tested there, the decision without a database at all
 * - and what is left here is the consequence: a refusal an operator can act on, on
 * the same path a bad `SIGNET_PUBLIC_URL` takes, or a report naming what was
 * verified.
 *
 * The refusal is a {@link ConfigError} because that is what it is. The role is
 * configuration, the remedy is to change configuration, and `index.ts` already
 * turns that error into a message and exit 1 before anything listens.
 *
 * Author: John Grimes
 */

import { classifyEnforcement, observeEnforcement } from "@signet/db";

import { ConfigError } from "./config.js";
import { logRecord } from "./observability/log.js";

import type { LogLevel } from "./observability/log.js";
import type { EnforcementVerdict, Executor } from "@signet/db";

/**
 * Where the offending role came from, appended to a refusal about one.
 *
 * Named because it is the thing to change, and because the alternative form the
 * chart uses would otherwise leave an operator searching a manifest for a variable
 * that is not in it. The variable's name is not a credential; its value is, and
 * neither this nor any message below contains any part of one.
 */
const CREDENTIAL_SOURCE =
  "Signet connects as the role named by SIGNET_DATABASE_URL, or by SIGNET_DATABASE_USER where the connection is configured in parts.";

/**
 * How a refusal reads, which depends on whether it is about the role at all.
 *
 * An absent schema is not: the remedy is to migrate, and naming the credential
 * variable would send an operator to rotate a role that is perfectly correct.
 */
function refusalFor(verdict: EnforcementVerdict): string {
  return verdict.outcome === "schema-absent"
    ? verdict.message
    : `${verdict.message} ${CREDENTIAL_SOURCE}`;
}

/**
 * Verifies that the policies bind this connection, before anything is served.
 *
 * Called once at startup, on the connection the server will serve on, because
 * every question it asks is about `current_user`.
 *
 * @param db - The server's own connection.
 * @param logLevel - The deployment's `SIGNET_LOG_LEVEL`, for the success report.
 * @returns The verdict, which is always healthy - anything else throws.
 * @throws {ConfigError} When the role is exempt from the policies, cannot reach a
 *   covered table, or the covered tables do not exist. Each message names what was
 *   found and the remedy for that specific cause.
 * @example
 * ```ts
 * const { db, close } = createDatabase({ url: config.databaseUrl });
 * await verifyEnforcement(db, config.logLevel);
 * serve({ fetch: app.fetch, port: config.port });
 * ```
 */
export async function verifyEnforcement(
  db: Executor,
  logLevel: LogLevel,
): Promise<EnforcementVerdict> {
  const verdict = classifyEnforcement(await observeEnforcement(db));

  if (verdict.outcome !== "healthy") {
    throw new ConfigError(refusalFor(verdict));
  }

  // Reported on success too. A control that is silent when it passes is one nobody
  // can tell is running, and the identity a deployment is actually serving as is
  // the fact an operator most needs to be able to read out of a log.
  logRecord(logLevel, "info", "signet.enforcement.verified", {
    role: verdict.role,
    tablesVerified: verdict.tablesVerified,
  });

  return verdict;
}
