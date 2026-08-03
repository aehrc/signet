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
 */

import { and, asc, eq, isNull, isNotNull, sql } from "drizzle-orm";

import { isPersonaSelectable } from "./predicates.js";
import { requireRow } from "./rows.js";
import { TenantScopeViolationError } from "./scope.js";
import { nowValue } from "./time.js";
import { endUsers } from "../schema/endpoints.js";

import type { Executor } from "./executor.js";
import type { EndpointScope } from "./scope.js";
import type { Endpoint, EndUser, NewEndUser } from "../schema/endpoints.js";

/** The caller-supplied half of an end user. */
export type EndUserInput = Omit<
  NewEndUser,
  "id" | "endpointId" | "createdAt" | "disabledAt"
>;

/** Creates an end user or persona on the scoped endpoint. */
export async function createEndUser(
  db: Executor,
  scope: EndpointScope,
  input: EndUserInput,
): Promise<EndUser> {
  const rows = await db
    .insert(endUsers)
    .values({ ...input, endpointId: scope.endpointId })
    .returning();
  return requireRow(rows, "insert into end_users");
}

/** Lists the scoped endpoint's users, by username. */
export async function listEndUsers(
  db: Executor,
  scope: EndpointScope,
): Promise<readonly EndUser[]> {
  return await db
    .select()
    .from(endUsers)
    .where(eq(endUsers.endpointId, scope.endpointId))
    .orderBy(asc(endUsers.username));
}

/** Reads one of the scoped endpoint's users. */
export async function getEndUser(
  db: Executor,
  scope: EndpointScope,
  endUserId: string,
): Promise<EndUser | undefined> {
  const [row] = await db
    .select()
    .from(endUsers)
    .where(
      and(
        eq(endUsers.endpointId, scope.endpointId),
        eq(endUsers.id, endUserId),
      ),
    )
    .limit(1);
  return row;
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
  db: Executor,
  scope: EndpointScope,
  username: string,
): Promise<EndUser | undefined> {
  const [row] = await db
    .select()
    .from(endUsers)
    .where(
      and(
        eq(endUsers.endpointId, scope.endpointId),
        eq(endUsers.username, username),
      ),
    )
    .limit(1);
  return row;
}

/**
 * Lists the personas an endpoint may offer in its picker.
 *
 * Empty on a production endpoint, whatever else is true. The endpoint row must
 * belong to the scope — a mismatch is a programming error, not a permission
 * failure, and is thrown rather than returned.
 *
 * The SQL filters on `is_persona` and enabled status, and
 * {@link isPersonaSelectable} is then applied to every row as well. The
 * duplication is deliberate: the predicate is the specification of who may be
 * picked, it is unit tested, and if a future edit loosens the query the rows still
 * have to pass it.
 */
export async function listSelectablePersonas(
  db: Executor,
  scope: EndpointScope,
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

  const rows = await db
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
  db: Executor,
  scope: EndpointScope,
): Promise<readonly EndUser[]> {
  return await db
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
  db: Executor,
  scope: EndpointScope,
  endUserId: string,
  patch: Partial<EndUserInput>,
): Promise<EndUser | undefined> {
  const [row] = await db
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
 * non-production endpoint — so this cannot be used to create a password-free
 * login on a production endpoint, only an account that cannot log in at all.
 */
export async function setEndUserPasswordHash(
  db: Executor,
  scope: EndpointScope,
  endUserId: string,
  passwordHash: string | null,
): Promise<EndUser | undefined> {
  return await updateEndUser(db, scope, endUserId, { passwordHash });
}

/**
 * Disables or re-enables a user.
 *
 * Disabling stops future authorizations but leaves already-issued tokens alone;
 * revoking those is a separate, explicit act, because "this person has left" and
 * "this person's tokens are compromised" are different situations.
 */
export async function setEndUserDisabled(
  db: Executor,
  scope: EndpointScope,
  endUserId: string,
  disabled: boolean,
  now?: Date,
): Promise<EndUser | undefined> {
  const [row] = await db
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
 * their tokens' `end_user_id` references — an authorization for a deleted user
 * must not be completable.
 *
 * @returns Whether a user was deleted.
 */
export async function deleteEndUser(
  db: Executor,
  scope: EndpointScope,
  endUserId: string,
): Promise<boolean> {
  const rows = await db
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

/** Counts the scoped endpoint's users, for the console's endpoint list. */
export async function countEndUsers(
  db: Executor,
  scope: EndpointScope,
): Promise<number> {
  const [row] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(endUsers)
    .where(eq(endUsers.endpointId, scope.endpointId));
  return row?.count ?? 0;
}
