/**
 * The `migrate` command.
 *
 * Run as `node dist/index.js migrate`, which is what the Helm chart's
 * pre-install/pre-upgrade hook Job invokes. It is a separate command rather than
 * something the server does at startup, and that matters at more than one replica:
 * three pods racing to apply the same migration is how a partially migrated schema
 * happens. A hook Job runs once, to completion, before any new pod is admitted.
 *
 * The migration files and the migrator itself both come from `@signet/db`, which is
 * the only package that depends on Drizzle - see its `migrations.ts` for why that
 * matters.
 *
 * Author: John Grimes
 */

import {
  applyMigrationsWithLock,
  createDatabase,
  resolveMigrationsFolder,
} from "@signet/db";

/**
 * Applies every outstanding migration and closes the connection.
 *
 * @param databaseUrl - The connection string to migrate.
 * @param log - Where progress goes. Injected so the command is testable, and so a
 *   deployment can see in the Job's logs what actually ran.
 */
export async function runMigrateCommand(
  databaseUrl: string,
  log: (message: string) => void = console.log,
): Promise<void> {
  log(`Applying migrations from ${resolveMigrationsFolder()}`);

  // A single connection: migrations are serial by nature, and a pool would leave
  // idle connections open while the Job waits to exit.
  const handle = createDatabase({ url: databaseUrl, maxConnections: 1 });
  try {
    await applyMigrationsWithLock(handle.db);
    log("Migrations applied");
  } finally {
    await handle.close();
  }
}
