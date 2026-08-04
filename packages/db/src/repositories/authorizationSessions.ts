/**
 * In-flight `/authorize` requests.
 *
 * A session is the server-side half of an authorization: it holds what the app
 * asked for while the user logs in, picks a patient and consents, across several
 * browser round trips. Everything security-bearing about the request - the
 * redirect URI, the PKCE challenge, the requested scopes - is recorded here at
 * the start and read from here at the end, never taken again from the browser.
 * That is what makes it impossible for a later step to widen an earlier decision.
 *
 * The session identifier is not a bearer credential: it travels in a cookie or a
 * URL that the user's own browser holds, and it grants nothing on its own. The
 * authorization code that *is* a credential lives in `./authorizationCodes.ts`
 * and is stored hashed.
 *
 * Author: John Grimes
 */

import { and, eq, gt, isNull, lte } from "drizzle-orm";

import { firstRow, requireRow } from "./rows.js";
import { executorFor } from "./scope.js";
import { nowValue } from "./time.js";
import { authorizationSessions } from "../schema/runtime.js";

import type { Executor } from "./executor.js";
import type { BoundClientScope, BoundEndpointScope } from "./scope.js";
import type {
  AuthorizationSession,
  NewAuthorizationSession,
} from "../schema/runtime.js";
import type { LaunchContext } from "@signet/core";

/**
 * The caller-supplied half of an authorization session.
 *
 * `endpointId` and `clientId` come from the scope, and the fields that later
 * steps fill in - the user, the resolved context, the consent timestamp - are not
 * settable at creation.
 */
export type AuthorizationSessionInput = Omit<
  NewAuthorizationSession,
  | "id"
  | "endpointId"
  | "clientId"
  | "createdAt"
  | "endUserId"
  | "resolvedContext"
  | "consentGrantedAt"
>;

/** Opens an authorization session for the scoped client. */
export async function createAuthorizationSession(
  scope: BoundClientScope,
  input: AuthorizationSessionInput,
): Promise<AuthorizationSession> {
  const rows = await executorFor(scope)
    .insert(authorizationSessions)
    .values({
      ...input,
      endpointId: scope.endpointId,
      clientId: scope.clientRowId,
    })
    .returning();
  return requireRow(rows, "insert into authorization_sessions");
}

/** Reads a session belonging to the scoped endpoint, whatever its state. */
export async function getAuthorizationSession(
  scope: BoundEndpointScope,
  sessionId: string,
): Promise<AuthorizationSession | undefined> {
  const [row] = await executorFor(scope)
    .select()
    .from(authorizationSessions)
    .where(
      and(
        eq(authorizationSessions.id, sessionId),
        eq(authorizationSessions.endpointId, scope.endpointId),
      ),
    )
    .limit(1);
  return row;
}

/**
 * Reads a session that is still within its lifetime.
 *
 * Expiry is applied in SQL, so a handler that only calls this cannot resume an
 * authorization that has timed out. The login and consent pages use it; the
 * console's diagnostics use {@link getAuthorizationSession}.
 */
export async function getLiveAuthorizationSession(
  scope: BoundEndpointScope,
  sessionId: string,
  now?: Date,
): Promise<AuthorizationSession | undefined> {
  const rows = await executorFor(scope)
    .select()
    .from(authorizationSessions)
    .where(
      and(
        eq(authorizationSessions.id, sessionId),
        eq(authorizationSessions.endpointId, scope.endpointId),
        gt(authorizationSessions.expiresAt, nowValue(now)),
      ),
    )
    .limit(1);
  return firstRow(rows);
}

/**
 * Records which end user authenticated.
 *
 * Only settable while the session has no user: re-authenticating into a session
 * that already belongs to somebody else would let one person complete another's
 * authorization. The guard is the `IS NULL` in the predicate, so it holds under
 * concurrency rather than depending on the handler's ordering.
 */
export async function attachEndUser(
  scope: BoundEndpointScope,
  sessionId: string,
  endUserId: string,
): Promise<AuthorizationSession | undefined> {
  const rows = await executorFor(scope)
    .update(authorizationSessions)
    .set({ endUserId })
    .where(
      and(
        eq(authorizationSessions.id, sessionId),
        eq(authorizationSessions.endpointId, scope.endpointId),
        isNull(authorizationSessions.endUserId),
      ),
    )
    .returning();
  return firstRow(rows);
}

/**
 * Records the launch context the authorization resolved to.
 *
 * The context is stored on the session as well as being referenced through
 * `launchContextId`, because the two answer different questions: the reference
 * says where it came from, and the copy says what was agreed. A swept or deleted
 * launch handle must not change what the user consented to.
 */
export async function setResolvedContext(
  scope: BoundEndpointScope,
  sessionId: string,
  context: LaunchContext,
  launchContextId?: string,
): Promise<AuthorizationSession | undefined> {
  const rows = await executorFor(scope)
    .update(authorizationSessions)
    .set({
      resolvedContext: context,
      ...(launchContextId === undefined ? {} : { launchContextId }),
    })
    .where(
      and(
        eq(authorizationSessions.id, sessionId),
        eq(authorizationSessions.endpointId, scope.endpointId),
      ),
    )
    .returning();
  return firstRow(rows);
}

/** Records that the end user granted consent. */
export async function recordSessionConsent(
  scope: BoundEndpointScope,
  sessionId: string,
  now?: Date,
): Promise<AuthorizationSession | undefined> {
  const rows = await executorFor(scope)
    .update(authorizationSessions)
    .set({ consentGrantedAt: nowValue(now) })
    .where(
      and(
        eq(authorizationSessions.id, sessionId),
        eq(authorizationSessions.endpointId, scope.endpointId),
      ),
    )
    .returning();
  return firstRow(rows);
}

/**
 * Abandons a session.
 *
 * Used when the user cancels at the consent screen. Deleting rather than marking
 * it cancelled: an abandoned session has no value to anyone, and its
 * authorization codes cascade away with it.
 *
 * @returns Whether a session was deleted.
 */
export async function deleteAuthorizationSession(
  scope: BoundEndpointScope,
  sessionId: string,
): Promise<boolean> {
  const rows = await executorFor(scope)
    .delete(authorizationSessions)
    .where(
      and(
        eq(authorizationSessions.id, sessionId),
        eq(authorizationSessions.endpointId, scope.endpointId),
      ),
    )
    .returning({ id: authorizationSessions.id });
  return rows.length > 0;
}

/**
 * Deletes sessions past their expiry.
 *
 * Their authorization codes go with them by cascade, which is why this runs after
 * the codes sweep in {@link sweepExpiredRuntimeRows} rather than instead of it:
 * the count reported for codes should reflect codes that expired on their own.
 *
 * @returns How many rows were deleted.
 */
export async function deleteExpiredAuthorizationSessions(
  db: Executor,
  now?: Date,
): Promise<number> {
  const rows = await db
    .delete(authorizationSessions)
    .where(lte(authorizationSessions.expiresAt, nowValue(now)))
    .returning({ id: authorizationSessions.id });
  return rows.length;
}
