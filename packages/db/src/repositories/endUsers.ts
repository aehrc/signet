/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * End users, personas, and their access to endpoints.
 *
 * An account belongs to a tenant and holds one username and one password there. It
 * may sign in only at endpoints an `end_user_endpoints` row admits it to, so the
 * functions here come in two kinds, and the scope they demand says which:
 *
 * - Managing the account itself - creating, editing, disabling, deleting it, and
 *   listing the tenant's accounts - takes a tenant scope and returns the
 *   {@link EndUser} row.
 * - Everything the OAuth layer reads - finding an account by username or id,
 *   offering personas, provisioning a federated sign-in - takes an endpoint scope
 *   and returns an {@link EndpointEndUser}: the account joined to its access row at
 *   that endpoint. An account with no access row is not found, so a sign-in, a
 *   persona pick or a refresh at an endpoint it has no access to fails as though the
 *   account did not exist.
 *
 * The tenant-level reads are named for the tenant (`getTenantEndUser`,
 * `listTenantEndUsers`) because an endpoint scope is also a tenant scope, and the
 * name is what stops an OAuth path from reaching for the read that skips the access
 * check.
 *
 * A persona is an end user with no password, which is a login with no
 * authentication. That is exactly what a connectathon wants and exactly what a
 * production endpoint must never offer, so {@link listSelectablePersonas} demands
 * the endpoint row and refuses outright when `is_production` is set. It takes the
 * row rather than a boolean the caller passes in: a boolean argument is one
 * inverted condition away from handing out unauthenticated access, whereas a row
 * can only have come from the database.
 *
 * Author: John Grimes
 */

import { and, asc, eq, isNull } from "drizzle-orm";

import { isPersonaSelectable } from "./predicates.js";
import { revokeRefreshTokensForSubject } from "./refreshTokens.js";
import { requireRow } from "./rows.js";
import { executorFor, TenantScopeViolationError } from "./scope.js";
import { nowValue } from "./time.js";
import { endpoints, endUserEndpoints, endUsers } from "../schema/endpoints.js";

import type { BoundEndpointScope, BoundTenantScope } from "./scope.js";
import type {
  Endpoint,
  EndpointEndUser,
  EndUser,
  EndUserEndpoint,
  NewEndUser,
} from "../schema/endpoints.js";
import type { SQL } from "drizzle-orm";

/** The caller-supplied half of an end user. */
export type EndUserInput = Omit<
  NewEndUser,
  "id" | "tenantId" | "createdAt" | "disabledAt"
>;

/** What an access row carries beyond the two identifiers it joins. */
export interface EndpointAccessFields {
  /** Relative FHIR reference, e.g. `Practitioner/123`, on this endpoint's server. */
  readonly fhirUserReference?: string | null;
  /** A persona's launch context on this endpoint. */
  readonly defaultContext?: EndUserEndpoint["defaultContext"];
}

/** One account's access to one endpoint, with what the console shows of the endpoint. */
export interface EndpointAccess extends EndUserEndpoint {
  readonly endpointSlug: string;
  readonly endpointName: string;
  readonly endpointKind: Endpoint["kind"];
  readonly endpointAuthMode: Endpoint["authMode"];
}

/** Creates an end user or persona in the scoped tenant, with access to nothing. */
export async function createEndUser(
  scope: BoundTenantScope,
  input: EndUserInput,
): Promise<EndUser> {
  const rows = await executorFor(scope)
    .insert(endUsers)
    .values({ ...input, tenantId: scope.tenantId })
    .returning();
  return requireRow(rows, "insert into end_users");
}

/** Lists the scoped tenant's users, by username. */
export async function listTenantEndUsers(
  scope: BoundTenantScope,
): Promise<readonly EndUser[]> {
  return await executorFor(scope)
    .select()
    .from(endUsers)
    .where(eq(endUsers.tenantId, scope.tenantId))
    .orderBy(asc(endUsers.username));
}

/**
 * Reads one of the scoped tenant's users, whatever endpoints they have access to.
 *
 * For managing the account. The OAuth layer must use {@link getEndUser}, which also
 * demands access to the endpoint.
 */
export async function getTenantEndUser(
  scope: BoundTenantScope,
  endUserId: string,
): Promise<EndUser | undefined> {
  const [row] = await executorFor(scope)
    .select()
    .from(endUsers)
    .where(
      and(eq(endUsers.tenantId, scope.tenantId), eq(endUsers.id, endUserId)),
    )
    .limit(1);
  return row;
}

/** The columns of an account as one endpoint sees it. */
const endpointEndUserColumns = {
  id: endUsers.id,
  tenantId: endUsers.tenantId,
  username: endUsers.username,
  passwordHash: endUsers.passwordHash,
  displayName: endUsers.displayName,
  email: endUsers.email,
  emailVerified: endUsers.emailVerified,
  roles: endUsers.roles,
  attributes: endUsers.attributes,
  isPersona: endUsers.isPersona,
  createdAt: endUsers.createdAt,
  disabledAt: endUsers.disabledAt,
  fhirUserReference: endUserEndpoints.fhirUserReference,
  defaultContext: endUserEndpoints.defaultContext,
};

/**
 * Reads the accounts with access to the scoped endpoint that a predicate selects.
 *
 * Written once, so that the access join cannot be present on the lookup by
 * identifier and absent on the lookup by username. The inner join is the access
 * check: an account with no row for this endpoint is not returned.
 */
async function selectEndpointEndUsers(
  scope: BoundEndpointScope,
  identifies?: SQL,
): Promise<EndpointEndUser[]> {
  return await executorFor(scope)
    .select(endpointEndUserColumns)
    .from(endUsers)
    .innerJoin(
      endUserEndpoints,
      and(
        eq(endUserEndpoints.endUserId, endUsers.id),
        eq(endUserEndpoints.endpointId, scope.endpointId),
      ),
    )
    .where(and(eq(endUsers.tenantId, scope.tenantId), identifies));
}

/** Reads a user with access to the scoped endpoint. */
export async function getEndUser(
  scope: BoundEndpointScope,
  endUserId: string,
): Promise<EndpointEndUser | undefined> {
  const [row] = await selectEndpointEndUsers(scope, eq(endUsers.id, endUserId));
  return row;
}

/** Lists the users with access to the scoped endpoint, by username. */
export async function listEndpointEndUsers(
  scope: BoundEndpointScope,
): Promise<readonly EndpointEndUser[]> {
  const rows = await selectEndpointEndUsers(scope);
  return rows.toSorted((a, b) => a.username.localeCompare(b.username));
}

/**
 * Finds a user with access to the scoped endpoint by the username they typed at its
 * login page.
 *
 * Usernames are unique per tenant: two tenants may each have an `alice`, and they
 * are different people. An account of this tenant with no access to this endpoint
 * is not returned, so it is refused exactly as an unknown username is.
 *
 * Disabled users are returned. The login handler must be able to tell a wrong
 * password from a disabled account for its audit event, while telling the browser
 * the same thing in both cases.
 */
export async function findEndUserByUsername(
  scope: BoundEndpointScope,
  username: string,
): Promise<EndpointEndUser | undefined> {
  const [row] = await selectEndpointEndUsers(
    scope,
    eq(endUsers.username, username),
  );
  return row;
}

/**
 * Lists the personas an endpoint may offer in its picker.
 *
 * Empty on a production endpoint, whatever else is true, and limited to personas
 * with access to the endpoint. The endpoint row must belong to the scope - a
 * mismatch is a programming error, not a permission failure, and is thrown rather
 * than returned.
 *
 * The SQL filters on `is_persona` and enabled status, and
 * {@link isPersonaSelectable} is then applied to every row as well. The
 * duplication is deliberate: the predicate is the specification of who may be
 * picked, it is unit tested, and if a future edit loosens the query the rows still
 * have to pass it.
 */
export async function listSelectablePersonas(
  scope: BoundEndpointScope,
  endpoint: Endpoint,
): Promise<readonly EndpointEndUser[]> {
  if (endpoint.id !== scope.endpointId) {
    throw new TenantScopeViolationError(
      `endpoint ${endpoint.id} is not the scoped endpoint ${scope.endpointId}`,
    );
  }
  if (endpoint.isProduction) {
    return [];
  }

  const rows = await selectEndpointEndUsers(
    scope,
    and(eq(endUsers.isPersona, true), isNull(endUsers.disabledAt)),
  );
  return rows
    .filter((user) => isPersonaSelectable(endpoint, user))
    .toSorted((a, b) => a.displayName.localeCompare(b.displayName));
}

/** Applies a patch to one of the scoped tenant's users. */
export async function updateEndUser(
  scope: BoundTenantScope,
  endUserId: string,
  patch: Partial<EndUserInput>,
): Promise<EndUser | undefined> {
  const [row] = await executorFor(scope)
    .update(endUsers)
    .set(patch)
    .where(
      and(eq(endUsers.tenantId, scope.tenantId), eq(endUsers.id, endUserId)),
    )
    .returning();
  return row;
}

/**
 * Replaces a user's password hash, or clears it.
 *
 * The password is the account's at every endpoint it has access to. Clearing it
 * leaves an account that cannot sign in with a password: a persona remains
 * selectable only on a non-production endpoint, and a local account waits for a
 * password to be set by an administrator or through an invitation link.
 */
export async function setEndUserPasswordHash(
  scope: BoundTenantScope,
  endUserId: string,
  passwordHash: string | null,
): Promise<EndUser | undefined> {
  return await updateEndUser(scope, endUserId, { passwordHash });
}

/**
 * Disables or re-enables a user, at every endpoint.
 *
 * Disabling stops future authorizations but leaves already-issued tokens alone;
 * revoking those is a separate, explicit act, because "this person has left" and
 * "this person's tokens are compromised" are different situations.
 */
export async function setEndUserDisabled(
  scope: BoundTenantScope,
  endUserId: string,
  disabled: boolean,
  now?: Date,
): Promise<EndUser | undefined> {
  const [row] = await executorFor(scope)
    .update(endUsers)
    .set({ disabledAt: disabled ? nowValue(now) : null })
    .where(
      and(eq(endUsers.tenantId, scope.tenantId), eq(endUsers.id, endUserId)),
    )
    .returning();
  return row;
}

/**
 * Deletes a user.
 *
 * Their access rows, in-flight authorization sessions and consents cascade away at
 * every endpoint - an authorization for a deleted user must not be completable.
 *
 * @returns Whether a user was deleted.
 */
export async function deleteEndUser(
  scope: BoundTenantScope,
  endUserId: string,
): Promise<boolean> {
  const rows = await executorFor(scope)
    .delete(endUsers)
    .where(
      and(eq(endUsers.tenantId, scope.tenantId), eq(endUsers.id, endUserId)),
    )
    .returning({ id: endUsers.id });
  return rows.length > 0;
}

/**
 * Gives a user access to the scoped endpoint, or updates the access they have.
 *
 * Idempotent on `(end_user_id, endpoint_id)`. Fields left undefined keep their
 * stored value on an update and are null on an insert. The account must belong to
 * the scoped tenant; the row-level security policy on `end_user_endpoints` refuses
 * one that does not, since the foreign key check alone would not.
 *
 * @param scope - The endpoint to give access to.
 * @param endUserId - The account.
 * @param fields - The endpoint-specific fields.
 */
export async function grantEndpointAccess(
  scope: BoundEndpointScope,
  endUserId: string,
  fields: EndpointAccessFields = {},
): Promise<EndUserEndpoint> {
  const set = Object.fromEntries(
    Object.entries(fields).filter(([, value]) => value !== undefined),
  );
  const rows = await executorFor(scope)
    .insert(endUserEndpoints)
    .values({ ...set, endUserId, endpointId: scope.endpointId })
    .onConflictDoUpdate({
      target: [endUserEndpoints.endUserId, endUserEndpoints.endpointId],
      // With nothing to change, a no-op update rather than DO NOTHING, so that the
      // existing row is still returned.
      set: Object.keys(set).length === 0 ? { endUserId } : set,
    })
    .returning();
  return requireRow(rows, "upsert into end_user_endpoints");
}

/**
 * Withdraws a user's access to the scoped endpoint.
 *
 * Their consents, management sessions and in-flight authorizations there cascade
 * away through the composite foreign keys on those tables, and their refresh tokens
 * there are revoked in the same transaction. Revoked rather than merely refused while
 * the access row is missing: giving access back, or a federated sign-in that grants
 * it again, must not revive the app delegations the withdrawal ended. Access tokens
 * already issued run to their expiry. Access to the tenant's other endpoints is
 * untouched.
 *
 * Must run inside one bound transaction, which `withTenantScope` provides.
 *
 * @param scope - The endpoint to withdraw access to.
 * @param endUserId - The account.
 * @param now - The revocation instant; the database's own by default.
 * @returns Whether the user had access to withdraw.
 */
export async function revokeEndpointAccess(
  scope: BoundEndpointScope,
  endUserId: string,
  now?: Date,
): Promise<boolean> {
  const rows = await executorFor(scope)
    .delete(endUserEndpoints)
    .where(
      and(
        eq(endUserEndpoints.endpointId, scope.endpointId),
        eq(endUserEndpoints.endUserId, endUserId),
      ),
    )
    .returning({ endUserId: endUserEndpoints.endUserId });
  if (rows.length === 0) {
    return false;
  }
  // A refresh token's subject is the account's id.
  await revokeRefreshTokensForSubject(scope, endUserId, now);
  return true;
}

/**
 * Lists access rows in the scoped tenant, with the endpoint each admits to.
 *
 * @param scope - The tenant.
 * @param endUserId - Limits the list to one account when given.
 * @returns Ordered by endpoint slug.
 */
export async function listEndpointAccess(
  scope: BoundTenantScope,
  endUserId?: string,
): Promise<readonly EndpointAccess[]> {
  return await executorFor(scope)
    .select({
      endUserId: endUserEndpoints.endUserId,
      endpointId: endUserEndpoints.endpointId,
      fhirUserReference: endUserEndpoints.fhirUserReference,
      defaultContext: endUserEndpoints.defaultContext,
      createdAt: endUserEndpoints.createdAt,
      endpointSlug: endpoints.slug,
      endpointName: endpoints.name,
      endpointKind: endpoints.kind,
      endpointAuthMode: endpoints.authMode,
    })
    .from(endUserEndpoints)
    .innerJoin(endpoints, eq(endpoints.id, endUserEndpoints.endpointId))
    .where(
      and(
        eq(endpoints.tenantId, scope.tenantId),
        endUserId === undefined
          ? undefined
          : eq(endUserEndpoints.endUserId, endUserId),
      ),
    )
    .orderBy(asc(endpoints.slug));
}

/** What a federated sign-in knows about the person, after claim mapping. */
export interface FederatedIdentity {
  /** `{issuer}#{sub}`, from the core helper. Stable across sign-ins. */
  readonly username: string;
  readonly displayName: string;
  readonly fhirUserReference: string | null;
  /** Null when no email claim is mapped, or the provider sent none. */
  readonly email: string | null;
  /** True only when the provider asserted `email_verified: true`. */
  readonly emailVerified: boolean;
  readonly roles: readonly string[];
  readonly attributes: Readonly<Record<string, unknown>>;
}

/**
 * Provisions or refreshes the account behind a federated sign-in, and its access to
 * the scoped endpoint.
 *
 * Idempotent on `(tenant_id, username)`, which is what makes the second sign-in
 * find the row the first one created rather than colliding with it - including a
 * sign-in at another endpoint of the tenant that trusts the same provider, which
 * reaches the same account. The unique index does the work: an
 * `ON CONFLICT DO UPDATE` cannot race the way a read-then-insert can, and two
 * browser tabs completing a callback at once are exactly the case that would
 * otherwise produce a duplicate-key error in front of a person who did nothing
 * wrong.
 *
 * Access to the endpoint is granted because the endpoint's provider configuration
 * is the rule that admits whoever the provider authenticates. Access to the
 * tenant's other endpoints is not touched.
 *
 * Every mapped field is refreshed on each sign-in, because the provider is the
 * source of truth for them - a person whose role was revoked upstream must not
 * keep it here because they were provisioned last year. The `fhirUser` reference
 * is written to the access row, since the claim mapping that produced it is this
 * endpoint's.
 *
 * What is never written is a password hash. A federated account authenticates
 * upstream and nowhere else; leaving the column null means `authenticateEndUser`
 * refuses it, so an account created this way cannot be used to sign in locally.
 * `is_persona` stays false for the same reason - a persona is selectable without
 * any credential at all.
 *
 * @param scope - The endpoint the sign-in happened at.
 * @param identity - The mapped claims from the provider.
 */
export async function upsertFederatedEndUser(
  scope: BoundEndpointScope,
  identity: FederatedIdentity,
): Promise<EndpointEndUser> {
  const values = {
    displayName: identity.displayName,
    email: identity.email,
    emailVerified: identity.emailVerified,
    roles: [...identity.roles],
    attributes: identity.attributes as Record<string, unknown>,
  };

  const rows = await executorFor(scope)
    .insert(endUsers)
    .values({
      tenantId: scope.tenantId,
      username: identity.username,
      ...values,
    })
    .onConflictDoUpdate({
      target: [endUsers.tenantId, endUsers.username],
      set: values,
    })
    .returning();
  const user = requireRow(rows, "upsert into end_users");

  const access = await grantEndpointAccess(scope, user.id, {
    fhirUserReference: identity.fhirUserReference,
  });
  return {
    ...user,
    fhirUserReference: access.fhirUserReference,
    defaultContext: access.defaultContext,
  };
}
