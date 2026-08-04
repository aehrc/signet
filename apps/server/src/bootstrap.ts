/**
 * The `bootstrap` command: bringing the first tenant and the first operator into
 * existence.
 *
 * Everything else in Signet is reachable through the console or the admin API, and
 * both require a membership of a tenant. Creating the first one therefore cannot be a
 * tenant operation - there is no tenant yet, and no account to authenticate as - so
 * it is a command run against the database instead. That is also why it is not a
 * public signup route: a deployment fronting somebody's clinical data should not
 * accept a self-service tenant from anybody who can reach the port.
 *
 * Idempotent, so it can sit in a Helm hook Job beside the migration and run on every
 * upgrade without failing the deployment. An account that already exists keeps its
 * password: overwriting one would let a re-run of the installer silently reset the
 * operator's credentials, and a rotation should be a deliberate act.
 *
 * The password is read from the environment rather than taken as an argument, because
 * an argument is visible in `ps` and in shell history.
 *
 * Author: John Grimes
 */

import {
  createAdminUser,
  createDatabase,
  createTenant,
  findAdminUserByEmail,
  getTenant,
  getTenantMembership,
  hashPassword,
  isUniqueViolation,
  resolveTenantScope,
  setTenantMemberRole,
  tenantScopeFromRow,
} from "@signet/db";

import type { AdminUser, Database, Tenant } from "@signet/db";

/** What a bootstrap needs. */
export interface BootstrapOptions {
  readonly databaseUrl: string;
  readonly tenantSlug: string;
  readonly tenantName: string;
  readonly email: string;
  readonly password: string;
  readonly displayName: string;
}

/** What a bootstrap did, so the caller can report it accurately. */
export interface BootstrapOutcome {
  readonly tenantCreated: boolean;
  readonly adminCreated: boolean;
  readonly membershipGranted: boolean;
}

/** The shortest password the command will accept. */
const MINIMUM_PASSWORD_LENGTH = 12;

/**
 * Reads the bootstrap options from the environment.
 *
 * @param env - The environment to read.
 * @param databaseUrl - The already-validated connection string.
 * @throws {Error} When a required variable is missing or the password is too short,
 *   naming the variable - a bootstrap that half-ran would leave a tenant nobody can
 *   sign in to.
 */
export function bootstrapOptionsFrom(
  env: Readonly<Record<string, string | undefined>>,
  databaseUrl: string,
): BootstrapOptions {
  const read = (name: string): string => {
    const value = env[name];
    if (value === undefined || value.trim().length === 0) {
      throw new Error(`${name} is required to bootstrap`);
    }
    return value.trim();
  };

  const password = read("SIGNET_BOOTSTRAP_PASSWORD");
  if (password.length < MINIMUM_PASSWORD_LENGTH) {
    throw new Error(
      `SIGNET_BOOTSTRAP_PASSWORD must be at least ${String(MINIMUM_PASSWORD_LENGTH)} characters`,
    );
  }

  const tenantSlug = read("SIGNET_BOOTSTRAP_TENANT");
  return {
    databaseUrl,
    tenantSlug,
    tenantName: env["SIGNET_BOOTSTRAP_TENANT_NAME"]?.trim() ?? tenantSlug,
    email: read("SIGNET_BOOTSTRAP_EMAIL"),
    password,
    displayName:
      env["SIGNET_BOOTSTRAP_NAME"]?.trim() ?? read("SIGNET_BOOTSTRAP_EMAIL"),
  };
}

/** Reads a tenant by slug, or undefined when there is none. */
async function readTenant(
  db: Database,
  slug: string,
): Promise<Tenant | undefined> {
  const scope = await resolveTenantScope(db, slug);
  // The scope proves the row exists but carries only its identifiers, so the row
  // itself is read through it - which is also the only way to obtain one here.
  return scope === undefined ? undefined : await getTenant(db, scope);
}

/**
 * Finds or creates the tenant.
 *
 * The unique violation is caught rather than pre-checked: two hook Jobs racing on a
 * rollout would both see no tenant and both insert, and the loser should join the
 * winner's tenant rather than fail the deployment.
 */
async function ensureTenant(
  db: Database,
  options: BootstrapOptions,
): Promise<{ readonly tenant: Tenant; readonly created: boolean }> {
  const existing = await readTenant(db, options.tenantSlug);
  if (existing !== undefined) {
    return { tenant: existing, created: false };
  }

  try {
    return {
      tenant: await createTenant(db, {
        slug: options.tenantSlug,
        name: options.tenantName,
      }),
      created: true,
    };
  } catch (error) {
    if (!isUniqueViolation(error)) {
      throw error;
    }
    const raced = await readTenant(db, options.tenantSlug);
    if (raced === undefined) {
      throw error;
    }
    return { tenant: raced, created: false };
  }
}

/**
 * Finds or creates the console identity.
 *
 * An existing account keeps its password. See the module header.
 */
async function ensureAdminUser(
  db: Database,
  options: BootstrapOptions,
): Promise<{ readonly user: AdminUser; readonly created: boolean }> {
  const existing = await findAdminUserByEmail(db, options.email);
  if (existing !== undefined) {
    return { user: existing, created: false };
  }

  try {
    return {
      user: await createAdminUser(db, {
        email: options.email,
        passwordHash: await hashPassword(options.password),
        displayName: options.displayName,
      }),
      created: true,
    };
  } catch (error) {
    if (!isUniqueViolation(error)) {
      throw error;
    }
    const raced = await findAdminUserByEmail(db, options.email);
    if (raced === undefined) {
      throw error;
    }
    return { user: raced, created: false };
  }
}

/**
 * Creates the first tenant and the first owner, if they are not already there.
 *
 * @param options - What to create.
 * @param log - Where progress goes. Injected so the command is testable, and so a
 *   deployment can see in the Job's logs what actually happened.
 */
export async function runBootstrapCommand(
  options: BootstrapOptions,
  log: (message: string) => void = console.log,
): Promise<BootstrapOutcome> {
  const handle = createDatabase({
    url: options.databaseUrl,
    maxConnections: 1,
  });
  try {
    const { tenant, created: tenantCreated } = await ensureTenant(
      handle.db,
      options,
    );
    log(
      tenantCreated
        ? `Created tenant ${tenant.slug}`
        : `Tenant ${tenant.slug} already exists`,
    );

    const { user, created: adminCreated } = await ensureAdminUser(
      handle.db,
      options,
    );
    log(
      adminCreated
        ? `Created console identity ${user.email}`
        : `Console identity ${user.email} already exists; its password is unchanged`,
    );

    const scope = tenantScopeFromRow(tenant);
    const membership = await getTenantMembership(handle.db, scope, user.id);
    let membershipGranted = false;
    if (membership === undefined) {
      const change = await setTenantMemberRole(
        handle.db,
        scope,
        user.id,
        "owner",
      );
      if (!change.ok) {
        throw new Error(`could not grant ownership: ${change.reason}`);
      }
      membershipGranted = true;
      log(`Granted ${user.email} ownership of ${tenant.slug}`);
    } else {
      log(`${user.email} is already a ${membership.role} of ${tenant.slug}`);
    }

    return { tenantCreated, adminCreated, membershipGranted };
  } finally {
    await handle.close();
  }
}
