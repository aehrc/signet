/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * End users and personas.
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

import { and, asc, eq, isNull, isNotNull, sql } from "drizzle-orm";

import { isPersonaSelectable } from "./predicates.js";
import { requireRow } from "./rows.js";
import { executorFor, TenantScopeViolationError } from "./scope.js";
import { nowValue } from "./time.js";
import { endUsers } from "../schema/endpoints.js";

import type { BoundEndpointScope } from "./scope.js";
import type { Endpoint, EndUser, NewEndUser } from "../schema/endpoints.js";
import type { SQL } from "drizzle-orm";

/** The caller-supplied half of an end user. */
export type EndUserInput = Omit<
  NewEndUser,
  "id" | "endpointId" | "createdAt" | "disabledAt"
>;

/** Creates an end user or persona on the scoped endpoint. */
export async function createEndUser(
  scope: BoundEndpointScope,
  input: EndUserInput,
): Promise<EndUser> {
  const rows = await executorFor(scope)
    .insert(endUsers)
    .values({ ...input, endpointId: scope.endpointId })
    .returning();
  return requireRow(rows, "insert into end_users");
}

/** Lists the scoped endpoint's users, by username. */
export async function listEndUsers(
  scope: BoundEndpointScope,
): Promise<readonly EndUser[]> {
  return await executorFor(scope)
    .select()
    .from(endUsers)
    .where(eq(endUsers.endpointId, scope.endpointId))
    .orderBy(asc(endUsers.username));
}

/**
 * Reads the one user a predicate selects within the scoped endpoint.
 *
 * Written once, so that the endpoint predicate cannot be present on the lookup by
 * identifier and absent on the lookup by username - which is where it matters
 * most, since usernames are unique only per endpoint.
 */
async function selectEndUser(
  scope: BoundEndpointScope,
  identifies: SQL | undefined,
): Promise<EndUser | undefined> {
  const [row] = await executorFor(scope)
    .select()
    .from(endUsers)
    .where(and(eq(endUsers.endpointId, scope.endpointId), identifies))
    .limit(1);
  return row;
}

/** Reads one of the scoped endpoint's users. */
export async function getEndUser(
  scope: BoundEndpointScope,
  endUserId: string,
): Promise<EndUser | undefined> {
  return await selectEndUser(scope, eq(endUsers.id, endUserId));
}

/**
 * Finds a user by the username they typed at the login page.
 *
 * Usernames are unique per endpoint, not globally: two endpoints may each have an
 * `alice`, and they are different people. The endpoint predicate is what makes
 * that true, so it is not optional.
 *
 * Disabled users are returned. The login handler must be able to tell a wrong
 * password from a disabled account for its audit event, while telling the browser
 * the same thing in both cases.
 */
export async function findEndUserByUsername(
  scope: BoundEndpointScope,
  username: string,
): Promise<EndUser | undefined> {
  return await selectEndUser(scope, eq(endUsers.username, username));
}

/**
 * Lists the personas an endpoint may offer in its picker.
 *
 * Empty on a production endpoint, whatever else is true. The endpoint row must
 * belong to the scope - a mismatch is a programming error, not a permission
 * failure, and is thrown rather than returned.
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
): Promise<readonly EndUser[]> {
  if (endpoint.id !== scope.endpointId) {
    throw new TenantScopeViolationError(
      `endpoint ${endpoint.id} is not the scoped endpoint ${scope.endpointId}`,
    );
  }
  if (endpoint.isProduction) {
    return [];
  }

  const rows = await executorFor(scope)
    .select()
    .from(endUsers)
    .where(
      and(
        eq(endUsers.endpointId, scope.endpointId),
        eq(endUsers.isPersona, true),
        isNull(endUsers.disabledAt),
      ),
    )
    .orderBy(asc(endUsers.displayName));

  return rows.filter((user) => isPersonaSelectable(endpoint, user));
}

/** Lists the endpoint's password-holding users, for the console. */
export async function listLocalEndUsers(
  scope: BoundEndpointScope,
): Promise<readonly EndUser[]> {
  return await executorFor(scope)
    .select()
    .from(endUsers)
    .where(
      and(
        eq(endUsers.endpointId, scope.endpointId),
        isNotNull(endUsers.passwordHash),
      ),
    )
    .orderBy(asc(endUsers.username));
}

/** Applies a patch to one of the scoped endpoint's users. */
export async function updateEndUser(
  scope: BoundEndpointScope,
  endUserId: string,
  patch: Partial<EndUserInput>,
): Promise<EndUser | undefined> {
  const [row] = await executorFor(scope)
    .update(endUsers)
    .set(patch)
    .where(
      and(
        eq(endUsers.endpointId, scope.endpointId),
        eq(endUsers.id, endUserId),
      ),
    )
    .returning();
  return row;
}

/**
 * Replaces a user's password hash, or clears it.
 *
 * Clearing it turns the account into a persona, which is only selectable on a
 * non-production endpoint - so this cannot be used to create a password-free
 * login on a production endpoint, only an account that cannot log in at all.
 */
export async function setEndUserPasswordHash(
  scope: BoundEndpointScope,
  endUserId: string,
  passwordHash: string | null,
): Promise<EndUser | undefined> {
  return await updateEndUser(scope, endUserId, { passwordHash });
}

/**
 * Disables or re-enables a user.
 *
 * Disabling stops future authorizations but leaves already-issued tokens alone;
 * revoking those is a separate, explicit act, because "this person has left" and
 * "this person's tokens are compromised" are different situations.
 */
export async function setEndUserDisabled(
  scope: BoundEndpointScope,
  endUserId: string,
  disabled: boolean,
  now?: Date,
): Promise<EndUser | undefined> {
  const [row] = await executorFor(scope)
    .update(endUsers)
    .set({ disabledAt: disabled ? nowValue(now) : null })
    .where(
      and(
        eq(endUsers.endpointId, scope.endpointId),
        eq(endUsers.id, endUserId),
      ),
    )
    .returning();
  return row;
}

/**
 * Deletes a user.
 *
 * Their in-flight authorization sessions and consents cascade away, and so do
 * their tokens' `end_user_id` references - an authorization for a deleted user
 * must not be completable.
 *
 * @returns Whether a user was deleted.
 */
export async function deleteEndUser(
  scope: BoundEndpointScope,
  endUserId: string,
): Promise<boolean> {
  const rows = await executorFor(scope)
    .delete(endUsers)
    .where(
      and(
        eq(endUsers.endpointId, scope.endpointId),
        eq(endUsers.id, endUserId),
      ),
    )
    .returning({ id: endUsers.id });
  return rows.length > 0;
}

/** What a federated sign-in knows about the person, after claim mapping. */
export interface FederatedIdentity {
  /** `{issuer}#{sub}`, from the core helper. Stable across sign-ins. */
  readonly username: string;
  readonly displayName: string;
  readonly fhirUserReference: string | null;
  readonly roles: readonly string[];
  readonly attributes: Readonly<Record<string, unknown>>;
}

/**
 * Provisions or refreshes the account behind a federated sign-in.
 *
 * Idempotent on `(endpoint_id, username)`, which is what makes the second sign-in
 * find the row the first one created rather than colliding with it. The unique
 * index does the work: an `ON CONFLICT DO UPDATE` cannot race the way a
 * read-then-insert can, and two browser tabs completing a callback at once are
 * exactly the case that would otherwise produce a duplicate-key error in front of
 * a person who did nothing wrong.
 *
 * Every mapped field is refreshed on each sign-in, because the provider is the
 * source of truth for them - a person whose role was revoked upstream must not
 * keep it here because they were provisioned last year.
 *
 * What is never written is a password hash. A federated account authenticates
 * upstream and nowhere else; leaving the column null means `authenticateEndUser`
 * refuses it, so an account created this way cannot be used to sign in locally.
 * `is_persona` stays false for the same reason - a persona is selectable without
 * any credential at all.
 *
 * @param scope - The endpoint the account belongs to.
 * @param identity - The mapped claims from the provider.
 */
export async function upsertFederatedEndUser(
  scope: BoundEndpointScope,
  identity: FederatedIdentity,
): Promise<EndUser> {
  const values = {
    displayName: identity.displayName,
    fhirUserReference: identity.fhirUserReference,
    roles: [...identity.roles],
    attributes: identity.attributes as Record<string, unknown>,
  };

  const rows = await executorFor(scope)
    .insert(endUsers)
    .values({
      endpointId: scope.endpointId,
      username: identity.username,
      ...values,
    })
    .onConflictDoUpdate({
      target: [endUsers.endpointId, endUsers.username],
      set: values,
    })
    .returning();

  return requireRow(rows, "upsert into end_users");
}

/** Counts the scoped endpoint's users, for the console's endpoint list. */
export async function countEndUsers(
  scope: BoundEndpointScope,
): Promise<number> {
  const [row] = await executorFor(scope)
    .select({ count: sql<number>`count(*)::int` })
    .from(endUsers)
    .where(eq(endUsers.endpointId, scope.endpointId));
  return row?.count ?? 0;
}
