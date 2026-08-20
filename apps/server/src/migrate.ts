/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The `migrate` command.
 *
 * Run as `node dist/index.js migrate`, which is what the Helm chart's
 * pre-install/pre-upgrade hook Job invokes. It is a separate command rather than
 * something the server does at startup, and that matters at more than one replica:
 * three pods racing to apply the same migration is how a partially migrated schema
 * happens. A hook Job runs once, to completion, before any new pod is admitted.
 *
 * It is also the only command that needs the owning identity. Migrations are DDL,
 * and the grants below are issued by the role that owns the objects being granted
 * - so the owner credential exists at exactly one point in a deployment's life
 * rather than sitting in the running pod. The server connects as the serving role,
 * which the tenant isolation policies bind.
 *
 * The migration files and the migrator itself both come from `@signet/db`, which is
 * the only package that depends on Drizzle - see its `migrations.ts` for why that
 * matters.
 *
 * Author: John Grimes
 */

import {
  applyMigrations,
  applyServingRolePrivileges,
  createDatabase,
  resolveMigrationsFolder,
  withMigrationLock,
} from "@signet/db";

/**
 * Applies every outstanding migration, grants the serving role, and closes the
 * connection.
 *
 * The two steps are one operation held under one advisory lock. A process that
 * observed the schema between them would find tables the serving role cannot
 * reach, which is indistinguishable from a migration that shipped a table
 * ungranted - and the grants are what stop that from being possible at all.
 *
 * @param ownerUrl - The owning identity's connection string. Migrations are DDL,
 *   and the grants must be issued by the role that owns the tables.
 * @param servingRole - The role the server connects as, parsed from
 *   `SIGNET_DATABASE_URL`. Named rather than connected as, so this command holds
 *   no credential it has no use for.
 * @param log - Where progress goes. Injected so the command is testable, and so a
 *   deployment can see in the Job's logs what actually ran.
 * @throws {Error} When a migration or a grant fails. Reporting success against a
 *   database whose serving role cannot reach its tables is the worst available
 *   outcome for a pre-upgrade hook: the failure would surface later as an empty
 *   result rather than as a failed Job.
 */
export async function runMigrateCommand(
  ownerUrl: string,
  servingRole: string,
  log: (message: string) => void = console.log,
): Promise<void> {
  log(`Applying migrations from ${resolveMigrationsFolder()}`);

  // A single connection: migrations are serial by nature, a pool would leave
  // idle connections open while the Job waits to exit, and a session-level
  // advisory lock belongs to the session that took it - a pooled unlock issued
  // on a different connection releases nothing.
  const handle = createDatabase({ url: ownerUrl, maxConnections: 1 });
  try {
    await withMigrationLock(handle.db, async () => {
      await applyMigrations(handle.db);
      log("Migrations applied");
      await applyServingRolePrivileges(handle.db, servingRole);
    });
    log(`Privileges granted to the serving role ${servingRole}`);
  } finally {
    await handle.close();
  }
}
