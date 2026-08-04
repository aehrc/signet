/**
 * The integration harness: a real Postgres, the real Hono app, no socket.
 *
 * The unit tests cover every pure judgement the OAuth layer makes. What they cannot
 * cover is the wiring - that `/authorize` writes the session the token endpoint later
 * reads, that a replayed code is refused by the database rather than by an `if`, that
 * a policy version is resolved through a scope that proves which tenant asked. Those
 * are properties of the composition, so they are asserted against the composition:
 * the app is driven through `app.request()`, which exercises routing, middleware and
 * body parsing exactly as a socket would, against a throwaway database.
 *
 * Skipped unless `SIGNET_TEST_DATABASE_URL` names a database that may be migrated.
 * CI provides one; a developer without one still gets the unit suites.
 *
 * Every fixture is created under a fresh tenant with a unique slug and deleted
 * afterwards, rather than by truncating. Vitest runs files in parallel, and a suite
 * that emptied shared tables would break whichever file happened to be running beside
 * it.
 *
 * Author: John Grimes
 */

import { SMART_BASELINE_PRESET } from "@signet/core";
import {
  applyMigrationsWithLock,
  createAdminUser,
  createApiToken,
  createAuditRecorder,
  createClient,
  createDatabase,
  createEndpoint,
  createEndUser,
  createPolicyVersion,
  createTenant,
  decryptSecret,
  deleteAdminUser,
  deleteTenant,
  endpointScopeFromRow,
  generateOpaqueToken,
  hashPassword,
  hashToken,
  insertEndpointKey,
  isTestSchemaReady,
  promoteNextEndpointKey,
  publishPolicy,
  setTenantMemberRole,
  tenantScopeFromRow,
  withTenantScope,
} from "@signet/db";

import { createApp } from "../app.js";
import {
  createRateLimitStore,
  createUnlimitedStore,
} from "../http/rateLimit.js";
import { generateEndpointKey } from "../keys/material.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { PolicyDocument } from "@signet/core";
import type {
  AdminUser,
  Client,
  Endpoint,
  EndpointScope,
  EndUser,
  Tenant,
  TenantRole,
  TenantScope,
} from "@signet/db";
import type { Hono } from "hono";

/** The database the integration suites run against, if one is configured. */
export const testDatabaseUrl = process.env["SIGNET_TEST_DATABASE_URL"];

/** The public origin the harness configures. Issuers are derived from it. */
export const TEST_PUBLIC_URL = "https://signet.test";

/** The FHIR server the test endpoint fronts, and every token's `aud`. */
export const TEST_FHIR_BASE_URL = "https://fhir.test/R4";

/** Thirty-two characters, the minimum the configuration accepts. */
export const TEST_MASTER_KEY = "0123456789abcdef0123456789abcdef";

/** The password every fixture user is created with. */
export const TEST_PASSWORD = "correct horse battery staple";

/** The secret every confidential-symmetric fixture client is created with. */
export const TEST_CLIENT_SECRET = "s3cret-value-for-tests";

/** A registered client, with the credential a test needs to present. */
export interface ClientFixture {
  readonly client: Client;
  /** Inline JWKS private key, for a `private_key_jwt` client. */
  readonly privateJwk?: Record<string, unknown>;
}

/** Everything an integration suite needs to make a request. */
export interface TestStack {
  readonly app: Hono<SignetEnvironment>;
  readonly context: ServerContext;
  readonly tenant: Tenant;
  readonly endpoint: Endpoint;
  readonly tenantScope: TenantScope;
  readonly scope: EndpointScope;
  readonly issuer: string;
  /** A public client with PKCE, registered for the code and refresh grants. */
  readonly publicClient: Client;
  /** A confidential client authenticating with {@link TEST_CLIENT_SECRET}. */
  readonly symmetricClient: Client;
  /** A confidential client authenticating with an inline JWKS. */
  readonly asymmetricClient: ClientFixture;
  /** A backend service, registered for `client_credentials` only. */
  readonly backendClient: ClientFixture;
  /** A local account with {@link TEST_PASSWORD}. */
  readonly user: EndUser;
  /** A password-free persona with a default patient context. */
  readonly persona: EndUser;
  /** A console identity holding `owner` in the fixture tenant. */
  readonly admin: AdminUser;
  /**
   * A console identity with no membership anywhere.
   *
   * The negative case that matters most for the admin API: a caller who is
   * authenticated but has no business seeing this tenant must be told the tenant
   * does not exist, not that they are forbidden from it.
   */
  readonly outsider: AdminUser;
  /**
   * Signs an admin in and returns the session cookie to present.
   *
   * Goes through `POST /api/v1/session` rather than inserting a row, so a suite
   * built on it exercises the real sign-in path.
   */
  readonly signIn: (as?: AdminUser) => Promise<string>;
  /** Mints a personal access token in the fixture tenant and returns it. */
  readonly mintApiToken: (role: TenantRole) => Promise<string>;
  /** Advances the harness clock. Requests see the new instant immediately. */
  readonly setNow: (at: Date) => void;
  readonly close: () => Promise<void>;
}

/** How a stack should differ from the default. */
export interface TestStackOptions {
  /** Overrides on the `endpoints` row. */
  readonly endpoint?: Partial<Parameters<typeof createEndpoint>[1]>;
  /** The policy to publish. Defaults to the SMART baseline preset. */
  readonly policy?: PolicyDocument;
  /** Omits the active signing key, to exercise the misconfigured-endpoint path. */
  readonly withoutSigningKey?: boolean;
  /** Permits outbound fetches to loopback, for a suite with a stub provider. */
  readonly allowPrivateOutboundFetches?: boolean;
  /** Applies the real rate limits, for the suite that asserts on them. */
  readonly rateLimits?: "enforced" | "unlimited";
}

/** Every scope the fixture clients are permitted to request. */
const ALLOWED_SCOPES = [
  "openid",
  "fhirUser",
  "profile",
  "launch",
  "launch/patient",
  "launch/encounter",
  "offline_access",
  "online_access",
  "patient/*.cruds",
  "user/*.cruds",
  "system/*.cruds",
];

let migrated = false;
let sequence = 0;

/**
 * Opens a connection, migrating only if nothing else has.
 *
 * Normally the schema is already there: the Vitest global setup migrates once
 * before any worker starts, precisely so that no DDL runs while other workers hold
 * row locks. The fallback covers running a single file outside that setup.
 */
async function connect(url: string) {
  const handle = createDatabase({ url, maxConnections: 5 });
  if (!migrated && !isTestSchemaReady()) {
    await applyMigrationsWithLock(handle.db);
    migrated = true;
  }
  return handle;
}

/**
 * Builds a fully configured endpoint and the clients that exercise it.
 *
 * @param options - Deviations from the default configuration.
 * @throws {Error} When no test database is configured. A suite should check
 *   {@link testDatabaseUrl} and skip rather than reach this.
 */
export async function createTestStack(
  options: TestStackOptions = {},
): Promise<TestStack> {
  if (testDatabaseUrl === undefined) {
    throw new Error("SIGNET_TEST_DATABASE_URL is not set");
  }

  const handle = await connect(testDatabaseUrl);
  const db = handle.db;

  sequence += 1;
  const suffix = `${String(process.pid)}-${String(sequence)}`;

  const tenant = await createTenant(db, {
    slug: `t-${suffix}`,
    name: `Test tenant ${suffix}`,
  });
  const tenantScope = tenantScopeFromRow(tenant);

  const endpoint = await withTenantScope(db, tenantScope, (bound) =>
    createEndpoint(bound, {
      slug: "fhir",
      name: "Test endpoint",
      fhirBaseUrl: TEST_FHIR_BASE_URL,
      // Non-production so personas are selectable and the picker accepts an
      // identifier that is not on a user's list.
      isProduction: false,
      consentMode: "always",
      supportsAuthorizePost: true,
      scopesSupported: ALLOWED_SCOPES,
      ...options.endpoint,
    }),
  );
  const scope = endpointScopeFromRow(tenantScope, endpoint);

  if (options.withoutSigningKey !== true) {
    const key = await generateEndpointKey("ES384", TEST_MASTER_KEY);
    await withTenantScope(db, scope, (bound) =>
      insertEndpointKey(bound, {
        kid: key.kid,
        algorithm: key.algorithm,
        publicJwk: key.publicJwk,
        privateJwkEncrypted: key.privateJwkEncrypted,
        status: "next",
      }),
    );
    // Inserted as `next` and promoted, rather than inserted as `active`: promotion is
    // what stamps `activated_at`, and `getActiveEndpointKey` orders by it. Setting the
    // status directly would produce a key the server cannot find.
    const promotion = await withTenantScope(db, scope, (bound) =>
      promoteNextEndpointKey(bound),
    );
    if (!promotion.ok) {
      throw new Error(
        `could not activate the signing key: ${promotion.reason}`,
      );
    }
  }

  const version = await createPolicyVersion(db, scope, {
    document: options.policy ?? SMART_BASELINE_PRESET,
    createdBy: null,
    note: "harness",
  });
  if (!version.ok) {
    throw new Error(`could not create a policy version: ${version.reason}`);
  }
  const published = await publishPolicy(db, scope, version.policy.version);
  if (!published.ok) {
    throw new Error(`could not publish the policy: ${published.reason}`);
  }

  const publicClient = await createClient(db, scope, {
    clientId: `public-${suffix}`,
    name: "Public app",
    clientType: "public",
    redirectUris: ["https://app.test/cb"],
    grantTypes: ["authorization_code", "refresh_token"],
    allowedScopes: ALLOWED_SCOPES,
    status: "active",
  });

  const symmetricClient = await createClient(db, scope, {
    clientId: `symmetric-${suffix}`,
    name: "Confidential app",
    clientType: "confidential-symmetric",
    secretHash: await hashPassword(TEST_CLIENT_SECRET),
    redirectUris: ["https://app.test/cb"],
    grantTypes: ["authorization_code", "refresh_token"],
    allowedScopes: ALLOWED_SCOPES,
    status: "active",
  });

  const asymmetricKey = await generateEndpointKey("RS384", TEST_MASTER_KEY);
  const asymmetricClient = await createClient(db, scope, {
    clientId: `asymmetric-${suffix}`,
    name: "Asymmetric app",
    clientType: "confidential-asymmetric",
    jwks: { keys: [asymmetricKey.publicJwk] },
    redirectUris: ["https://app.test/cb"],
    grantTypes: ["authorization_code", "refresh_token"],
    allowedScopes: ALLOWED_SCOPES,
    status: "active",
  });

  const backendKey = await generateEndpointKey("RS384", TEST_MASTER_KEY);
  const backendClient = await createClient(db, scope, {
    clientId: `backend-${suffix}`,
    name: "Backend service",
    clientType: "confidential-asymmetric",
    jwks: { keys: [backendKey.publicJwk] },
    grantTypes: ["client_credentials"],
    allowedScopes: ALLOWED_SCOPES,
    status: "active",
  });

  const user = await createEndUser(db, scope, {
    username: "clinician",
    passwordHash: await hashPassword(TEST_PASSWORD),
    fhirUserReference: "Practitioner/prac-1",
    displayName: "Test Clinician",
    roles: ["practitioner"],
    attributes: { patients: ["pat-1", "pat-2"] },
  });

  const persona = await createEndUser(db, scope, {
    username: "persona-patient",
    fhirUserReference: "Patient/pat-9",
    displayName: "Persona Patient",
    isPersona: true,
    defaultContext: { patient: "pat-9" },
  });

  const admin = await createAdminUser(db, {
    email: `admin-${suffix}@signet.test`,
    passwordHash: await hashPassword(TEST_PASSWORD),
    displayName: "Test Admin",
  });
  const membership = await withTenantScope(db, tenantScope, (bound) =>
    setTenantMemberRole(bound, admin.id, "owner"),
  );
  if (!membership.ok) {
    throw new Error(`could not grant membership: ${membership.reason}`);
  }

  const outsider = await createAdminUser(db, {
    email: `outsider-${suffix}@signet.test`,
    passwordHash: await hashPassword(TEST_PASSWORD),
    displayName: "Test Outsider",
  });

  let now = new Date();
  const context: ServerContext = {
    config: {
      port: 3000,
      publicUrl: TEST_PUBLIC_URL,
      databaseUrl: testDatabaseUrl,
      masterKey: TEST_MASTER_KEY,
      logLevel: "error",
      webRoot: undefined,
      // Off by default, as in production. The federation suite turns it on, because
      // its stub identity provider is a loopback server and the guard exists to
      // refuse exactly that.
      allowPrivateOutboundFetches: options.allowPrivateOutboundFetches ?? false,
    },
    db,
    // Audit failures are surfaced rather than swallowed: a suite that silently lost
    // its audit events would still pass the assertions that matter, and then the
    // audit assertions would fail mysteriously.
    audit: createAuditRecorder((failure) => {
      throw new Error(
        `audit write failed for ${failure.action}: ${String(failure.error)}`,
      );
    }),
    clock: () => now,
    // Opted out by default: the suites drive far more sign-ins per frozen minute
    // than a person could, which is the traffic the limiter exists to refuse. A
    // suite that wants the real thing asks for it.
    rateLimits:
      options.rateLimits === "enforced"
        ? createRateLimitStore()
        : createUnlimitedStore(),
  };

  const app = createApp(context);

  return {
    app,
    context,
    tenant,
    endpoint,
    tenantScope,
    scope,
    issuer: `${TEST_PUBLIC_URL}/t/${tenant.slug}/e/${endpoint.slug}`,
    publicClient,
    symmetricClient,
    asymmetricClient: {
      client: asymmetricClient,
      privateJwk: await decryptedJwk(asymmetricKey.privateJwkEncrypted),
    },
    backendClient: {
      client: backendClient,
      privateJwk: await decryptedJwk(backendKey.privateJwkEncrypted),
    },
    user,
    persona,
    admin,
    outsider,
    signIn: async (as = admin) => {
      const response = await app.request("/api/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: as.email, password: TEST_PASSWORD }),
      });
      const cookie = response.headers.get("set-cookie");
      if (response.status !== 200 || cookie === null) {
        throw new Error(
          `could not sign ${as.email} in: ${String(response.status)} ${await response.text()}`,
        );
      }
      // Only the name=value pair is sent back by a browser; the attributes are
      // instructions to it, and passing them on would make the header invalid.
      return cookie.split(";", 1)[0] ?? "";
    },
    mintApiToken: async (role) => {
      const value = generateOpaqueToken();
      const tokenHash = await hashToken(value);
      await withTenantScope(db, tenantScope, (bound) =>
        createApiToken(bound, {
          name: `token-${role}`,
          tokenHash,
          role,
          createdBy: admin.id,
          expiresAt: null,
        }),
      );
      return value;
    },
    setNow: (at) => {
      now = at;
    },
    close: async () => {
      // Deleting the tenant cascades to everything the fixtures created, audit
      // events included. Console identities are not tenant-owned, so they are
      // removed explicitly; their sessions and memberships cascade from them.
      await withTenantScope(db, tenantScope, (bound) => deleteTenant(bound));
      await deleteAdminUser(db, admin.id);
      await deleteAdminUser(db, outsider.id);
      await handle.close();
    },
  };
}

/**
 * Recovers a generated private key as a JWK, for a test that must sign as a client.
 *
 * The harness stores client keys the same way an operator would register them -
 * public half inline, private half never persisted - so the private half has to come
 * back out of the envelope it was generated into.
 */
async function decryptedJwk(
  ciphertext: string,
): Promise<Record<string, unknown>> {
  return JSON.parse(await decryptSecret(ciphertext, TEST_MASTER_KEY)) as Record<
    string,
    unknown
  >;
}
