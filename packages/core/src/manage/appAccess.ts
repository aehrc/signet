/**
 * The management page's view of who can act on a person's record.
 *
 * Two facts answer that question, and each can exist without the other. A stored
 * consent is a standing grant - the next authorization will not ask again - and lives
 * only on endpoints whose consent mode is `remember`. A live token is access an app
 * holds right now, and every endpoint mints those. An `always`-mode endpoint stores no
 * consents at all, so a page built from consents alone shows "no apps have access" to
 * a person whose record several apps can read this minute.
 *
 * This module merges the two into one list, in pure functions, so the management
 * endpoint and anything else that answers the question agree by construction.
 *
 * Author: John Grimes
 */

/** A stored consent joined with the client it names. */
export interface ConsentGrant {
  readonly consentId: string;
  /** The client's public identifier, as apps present it. */
  readonly clientId: string;
  readonly clientName: string;
  readonly logoUrl: string | null;
  /** The consented scopes, space-delimited. */
  readonly scope: string;
  readonly grantedAt: Date;
  readonly expiresAt: Date | null;
  readonly revokedAt: Date | null;
}

/** The lifecycle half of an issued token, access or refresh alike. */
export interface IssuedToken {
  /** The client's row id, which is what token rows carry. */
  readonly clientRowId: string;
  /** The token's scopes, space-delimited. */
  readonly scope: string;
  readonly issuedAt: Date;
  readonly expiresAt: Date;
  readonly revokedAt: Date | null;
}

/** A client the endpoint knows, for naming token-backed entries. */
export interface KnownClient {
  readonly rowId: string;
  readonly clientId: string;
  readonly name: string;
  readonly logoUrl: string | null;
}

/** One row on the management page. */
export interface AppAccessEntry {
  /** The consent behind a standing entry, or null for one backed only by tokens. */
  readonly consentId: string | null;
  readonly clientId: string;
  readonly clientName: string;
  readonly logoUrl: string | null;
  readonly scope: readonly string[];
  /** When the grant was given, or when the earliest live token was issued. */
  readonly grantedAt: Date;
  readonly expiresAt: Date | null;
  readonly revokedAt: Date | null;
  /** Whether the app can act right now, which is what a person wants to know. */
  readonly active: boolean;
  /** Whether a stored consent backs this entry, making it a standing grant. */
  readonly standing: boolean;
}

/** What the management page shows. */
export interface AppAccessView {
  readonly entries: readonly AppAccessEntry[];
  /** Live tokens only: a revoked or expired row is not access anybody holds. */
  readonly liveTokens: { readonly access: number; readonly refresh: number };
}

/** Whether a token can still be presented. */
function isLive(token: IssuedToken, now: Date): boolean {
  return token.revokedAt === null && token.expiresAt > now;
}

/** Whether a consent still stands. */
function consentIsActive(grant: ConsentGrant, now: Date): boolean {
  return (
    grant.revokedAt === null &&
    (grant.expiresAt === null || grant.expiresAt > now)
  );
}

/** Splits a space-delimited scope string into its scopes. */
function splitScope(scope: string): readonly string[] {
  return scope.split(" ").filter((candidate) => candidate.length > 0);
}

/** A consent as the page shows it. */
function consentEntry(grant: ConsentGrant, now: Date): AppAccessEntry {
  return {
    consentId: grant.consentId,
    clientId: grant.clientId,
    clientName: grant.clientName,
    logoUrl: grant.logoUrl,
    scope: splitScope(grant.scope),
    grantedAt: grant.grantedAt,
    expiresAt: grant.expiresAt,
    revokedAt: grant.revokedAt,
    active: consentIsActive(grant, now),
    standing: true,
  };
}

/** One client's live tokens folded into a single page entry. */
function tokenEntry(
  client: KnownClient,
  tokens: readonly IssuedToken[],
): AppAccessEntry {
  const scope = [
    ...new Set(tokens.flatMap((token) => splitScope(token.scope))),
  ];
  const grantedAt = new Date(
    Math.min(...tokens.map((token) => token.issuedAt.getTime())),
  );
  const expiresAt = new Date(
    Math.max(...tokens.map((token) => token.expiresAt.getTime())),
  );
  return {
    consentId: null,
    clientId: client.clientId,
    clientName: client.name,
    logoUrl: client.logoUrl,
    scope,
    grantedAt,
    expiresAt,
    revokedAt: null,
    active: true,
    standing: false,
  };
}

/**
 * Merges stored consents and live tokens into the management page's list.
 *
 * Consent entries come first, in the order given, revoked and expired ones included
 * and marked - removing them would look like the record had been lost rather than
 * ended. After them, one entry per client that holds a live token but no active
 * consent, so that access granted on an endpoint that stores no consents is still
 * visible and revocable. A token whose client is missing from `clients` cannot be
 * named and is omitted from the list, though it still counts as live.
 *
 * @param input - The consents, tokens and clients read for one end user, and the
 *   current instant to judge liveness against.
 * @param input.consents - The user's stored consents, joined with their clients.
 * @param input.accessTokens - Every access token row recorded for the user.
 * @param input.refreshTokens - Every refresh token row recorded for the user.
 * @param input.clients - The endpoint's clients, for naming token-backed entries.
 * @param input.now - The instant to judge liveness against.
 * @returns The page's entries, and how many live tokens of each kind exist.
 */
export function buildAppAccess(input: {
  readonly consents: readonly ConsentGrant[];
  readonly accessTokens: readonly IssuedToken[];
  readonly refreshTokens: readonly IssuedToken[];
  readonly clients: readonly KnownClient[];
  readonly now: Date;
}): AppAccessView {
  const { consents, accessTokens, refreshTokens, clients, now } = input;

  const liveAccess = accessTokens.filter((token) => isLive(token, now));
  const liveRefresh = refreshTokens.filter((token) => isLive(token, now));

  const consentEntries = consents.map((grant) => consentEntry(grant, now));
  const activelyConsentedClientIds = new Set(
    consentEntries
      .filter((entry) => entry.active)
      .map((entry) => entry.clientId),
  );

  const byClientRowId = new Map<string, IssuedToken[]>();
  for (const token of [...liveAccess, ...liveRefresh]) {
    const group = byClientRowId.get(token.clientRowId) ?? [];
    group.push(token);
    byClientRowId.set(token.clientRowId, group);
  }

  const clientsByRowId = new Map(
    clients.map((client) => [client.rowId, client]),
  );
  const tokenEntries = [...byClientRowId.entries()]
    .flatMap(([rowId, tokens]) => {
      const client = clientsByRowId.get(rowId);
      if (client === undefined) {
        return [];
      }
      if (activelyConsentedClientIds.has(client.clientId)) {
        // The consent entry already tells the person this app can act; a second
        // row for the same client would read as two separate grants.
        return [];
      }
      return [tokenEntry(client, tokens)];
    })
    .toSorted((a, b) => b.grantedAt.getTime() - a.grantedAt.getTime());

  return {
    entries: [...consentEntries, ...tokenEntries],
    liveTokens: { access: liveAccess.length, refresh: liveRefresh.length },
  };
}
