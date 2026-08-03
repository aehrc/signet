/**
 * Versioned scope→claims policies.
 *
 * Two invariants live here, and both are enforced with the database rather than
 * with care.
 *
 * Version numbers are allocated under a lock on the endpoint row. Two
 * administrators saving at once would otherwise both compute `max(version) + 1`,
 * and one of them would lose the save to a unique violation — or, worse, the read
 * would be non-repeatable and both would succeed with the same number were the
 * index ever relaxed. Locking a row that certainly exists (the endpoint) is the
 * standard way to serialise the allocation of a key that does not exist yet.
 *
 * Publication is a swap inside a transaction, and the target is checked *before*
 * anything is unpublished. Publishing a version that turns out not to exist must
 * leave the previously published one alone; getting that order wrong would take
 * the endpoint's policy away and put nothing in its place, which stops the
 * endpoint issuing tokens at all.
 */

import { and, asc, desc, eq, sql } from "drizzle-orm";

import { nextPolicyVersion } from "./predicates.js";
import { firstRow, requireRow } from "./rows.js";
import { endpoints } from "../schema/endpoints.js";
import { clientPolicyOverrides, policies } from "../schema/policies.js";

import type { Executor } from "./executor.js";
import type { ClientScope, EndpointScope } from "./scope.js";
import type {
  ClientPolicyOverride,
  NewPolicy,
  Policy,
} from "../schema/policies.js";
import type { PolicyDocument } from "@signet/core";

/** The caller-supplied half of a policy version. */
export type PolicyInput = Pick<NewPolicy, "document" | "createdBy" | "note">;

/**
 * Takes the lock that serialises version allocation for one endpoint.
 *
 * @returns Whether the endpoint still exists.
 */
async function lockEndpoint(
  tx: Executor,
  scope: EndpointScope,
): Promise<boolean> {
  const rows = await tx
    .select({ id: endpoints.id })
    .from(endpoints)
    .where(
      and(
        eq(endpoints.id, scope.endpointId),
        eq(endpoints.tenantId, scope.tenantId),
      ),
    )
    .for("update");
  return rows.length > 0;
}

/** Why a policy operation could not be completed. */
export type PolicyRefusal = "endpoint-not-found" | "version-not-found";

/** The outcome of writing a policy version. */
export type PolicyWrite =
  | { readonly ok: true; readonly policy: Policy }
  | { readonly ok: false; readonly reason: PolicyRefusal };

/**
 * Appends a new version of the scoped endpoint's policy.
 *
 * Versions are immutable, so editing a policy means creating one of these. The
 * new version is unpublished: saving must never change what the endpoint is
 * currently issuing, or the editor would be a live control surface on production
 * token contents.
 */
export async function createPolicyVersion(
  db: Executor,
  scope: EndpointScope,
  input: PolicyInput,
): Promise<PolicyWrite> {
  return await db.transaction(async (tx) => {
    if (!(await lockEndpoint(tx, scope))) {
      return { ok: false, reason: "endpoint-not-found" };
    }

    const [highest] = await tx
      .select({ version: sql<number | null>`max(${policies.version})` })
      .from(policies)
      .where(eq(policies.endpointId, scope.endpointId));

    const rows = await tx
      .insert(policies)
      .values({
        ...input,
        endpointId: scope.endpointId,
        version: nextPolicyVersion(highest?.version ?? null),
      })
      .returning();

    return { ok: true, policy: requireRow(rows, "insert into policies") };
  });
}

/** Lists the scoped endpoint's policy versions, newest first. */
export async function listPolicyVersions(
  db: Executor,
  scope: EndpointScope,
): Promise<readonly Policy[]> {
  return await db
    .select()
    .from(policies)
    .where(eq(policies.endpointId, scope.endpointId))
    .orderBy(desc(policies.version));
}

/** Reads one version of the scoped endpoint's policy. */
export async function getPolicyVersion(
  db: Executor,
  scope: EndpointScope,
  version: number,
): Promise<Policy | undefined> {
  const [row] = await db
    .select()
    .from(policies)
    .where(
      and(
        eq(policies.endpointId, scope.endpointId),
        eq(policies.version, version),
      ),
    )
    .limit(1);
  return row;
}

/**
 * Reads the scoped endpoint's published policy.
 *
 * At most one row can satisfy this, by partial unique index. The `limit` is
 * therefore belt and braces rather than a tie-break — if it ever mattered, the
 * index would already have been dropped and token issuance would be ambiguous.
 */
export async function getPublishedPolicy(
  db: Executor,
  scope: EndpointScope,
): Promise<Policy | undefined> {
  const [row] = await db
    .select()
    .from(policies)
    .where(
      and(
        eq(policies.endpointId, scope.endpointId),
        eq(policies.published, true),
      ),
    )
    .orderBy(asc(policies.version))
    .limit(1);
  return row;
}

/**
 * Makes one version the scoped endpoint's published policy.
 *
 * Exactly one version is published when this returns successfully: the previous
 * one is unpublished and the target published, in a single transaction, with the
 * endpoint row locked so that two concurrent publishes cannot interleave into a
 * state the partial unique index would reject.
 */
export async function publishPolicy(
  db: Executor,
  scope: EndpointScope,
  version: number,
): Promise<PolicyWrite> {
  return await db.transaction(async (tx) => {
    if (!(await lockEndpoint(tx, scope))) {
      return { ok: false, reason: "endpoint-not-found" };
    }

    // Checked before anything is unpublished; see the module header.
    const target = await getPolicyVersion(tx, scope, version);
    if (target === undefined) {
      return { ok: false, reason: "version-not-found" };
    }

    await tx
      .update(policies)
      .set({ published: false })
      .where(
        and(
          eq(policies.endpointId, scope.endpointId),
          eq(policies.published, true),
        ),
      );

    const rows = await tx
      .update(policies)
      .set({ published: true })
      .where(eq(policies.id, target.id))
      .returning();

    return { ok: true, policy: requireRow(rows, "publish policies row") };
  });
}

/** Reads the scoped client's policy override, if it has one. */
export async function getClientPolicyOverride(
  db: Executor,
  scope: ClientScope,
): Promise<ClientPolicyOverride | undefined> {
  const [row] = await db
    .select()
    .from(clientPolicyOverrides)
    .where(eq(clientPolicyOverrides.clientId, scope.clientRowId))
    .limit(1);
  return row;
}

/**
 * Sets the scoped client's policy override.
 *
 * The document replaces the endpoint's policy outright rather than merging with
 * it. Both documents are ordered rule lists in which position decides the
 * outcome, and there is no ordering of the union that is obviously right, so
 * Signet does not invent one.
 */
export async function setClientPolicyOverride(
  db: Executor,
  scope: ClientScope,
  document: PolicyDocument,
): Promise<ClientPolicyOverride> {
  const rows = await db
    .insert(clientPolicyOverrides)
    .values({ clientId: scope.clientRowId, document })
    .onConflictDoUpdate({
      target: clientPolicyOverrides.clientId,
      set: { document },
    })
    .returning();
  return requireRow(rows, "upsert into client_policy_overrides");
}

/**
 * Removes the scoped client's policy override, restoring the endpoint's policy.
 *
 * @returns Whether an override was removed.
 */
export async function deleteClientPolicyOverride(
  db: Executor,
  scope: ClientScope,
): Promise<boolean> {
  const rows = await db
    .delete(clientPolicyOverrides)
    .where(eq(clientPolicyOverrides.clientId, scope.clientRowId))
    .returning({ clientId: clientPolicyOverrides.clientId });
  return rows.length > 0;
}

/** The policy a token issuance will actually be evaluated against. */
export interface EffectivePolicy {
  readonly source: "client-override" | "endpoint";
  readonly document: PolicyDocument;
  /** The version the document came from; null for a client override. */
  readonly version: number | null;
  /** The `policies` row identifier; null for a client override. */
  readonly policyId: string | null;
}

/**
 * Resolves which policy governs a token for the scoped client.
 *
 * A client override wins over the endpoint's published policy. Both are returned
 * with enough provenance for the audit event to name the exact document that
 * authorised the token, which is the whole reason versions are immutable rows.
 *
 * @returns Undefined when the endpoint has no published policy and the client has
 *   no override. The caller must refuse to issue a token: an endpoint with no
 *   policy grants nothing, and inventing a permissive default here would be the
 *   single worst failure mode available to this codebase.
 */
export async function getEffectivePolicy(
  db: Executor,
  scope: ClientScope,
): Promise<EffectivePolicy | undefined> {
  const override = await getClientPolicyOverride(db, scope);
  if (override !== undefined) {
    return {
      source: "client-override",
      document: override.document,
      version: null,
      policyId: null,
    };
  }

  const published = await getPublishedPolicy(db, scope);
  if (published === undefined) {
    return undefined;
  }

  return {
    source: "endpoint",
    document: published.document,
    version: published.version,
    policyId: published.id,
  };
}

/**
 * Reads the highest version number the scoped endpoint has allocated.
 *
 * Exposed for the console, which shows "version 7 of 7" beside the editor.
 */
export async function getLatestPolicyVersion(
  db: Executor,
  scope: EndpointScope,
): Promise<Policy | undefined> {
  const rows = await db
    .select()
    .from(policies)
    .where(eq(policies.endpointId, scope.endpointId))
    .orderBy(desc(policies.version))
    .limit(1);
  return firstRow(rows);
}
