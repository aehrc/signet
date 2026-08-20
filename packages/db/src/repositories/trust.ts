/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The two rules that turn vouched registration and ticket exchange on.
 *
 * Everything here reads or writes at most one row, because both tables key on
 * `endpoint_id`: an endpoint trusts at most one anchor and at most one ticket
 * issuer. That is why the writes are upserts rather than an insert and an update
 * a caller has to choose between - "configure this endpoint's anchor" is one
 * operation whether or not a rule was already there, and splitting it would
 * invite a read-then-write with a race in the middle.
 *
 * The reads answer *undefined* for an endpoint with no rule, and that value is
 * load-bearing rather than incidental: it is what makes the registration route
 * answer 404 and the token endpoint answer `unsupported_grant_type`. No function
 * here has a default to fall back to, because there is no such thing as a default
 * anchor.
 *
 * Deletion returns whether a row went, and deleting a rule that is not there is
 * not an error: the caller asked for an endpoint with no anchor, and it has none.
 * Removing a rule is also not revocation of the clients it vouched for - those
 * carry their own expiry, and it is `clients.vouching_expires_at` that stops
 * them, not the presence of the anchor that created them.
 *
 * Author: John Grimes
 */

import { eq } from "drizzle-orm";

import { firstRow, requireRow } from "./rows.js";
import { executorFor } from "./scope.js";
import { nowValue } from "./time.js";
import {
  endpointTicketIssuers,
  endpointTrustAnchors,
} from "../schema/trust.js";

import type { BoundEndpointScope } from "./scope.js";
import type {
  EndpointTicketIssuer,
  EndpointTrustAnchor,
  NewEndpointTicketIssuer,
  NewEndpointTrustAnchor,
} from "../schema/trust.js";

/** The caller-supplied half of a trust anchor rule. */
export type TrustAnchorInput = Omit<
  NewEndpointTrustAnchor,
  "endpointId" | "createdAt" | "updatedAt"
>;

/** The caller-supplied half of a ticket issuer rule. */
export type TicketIssuerInput = Omit<
  NewEndpointTicketIssuer,
  "endpointId" | "createdAt" | "updatedAt"
>;

/**
 * Configures the scoped endpoint's trust anchor, replacing any it already had.
 *
 * @param scope - The endpoint the rule belongs to, bound to the transaction that
 *   declared its tenant.
 * @param input - The anchor's issuer, key address and vouching cap.
 * @param now - Stamps `updated_at`; defaults to the transaction clock.
 * @returns The stored rule.
 * @throws {Error} When the write returns no row, which would mean the statement
 *   ran against an endpoint the policies hide.
 * @example
 * ```ts
 * await withTenantScope(db, endpointScope, (bound) =>
 *   upsertEndpointTrustAnchor(bound, {
 *     issuer: "https://anchor.example.org",
 *     jwksUri: "https://anchor.example.org/jwks",
 *     maxVouchingDays: 30,
 *   }),
 * );
 * ```
 */
export async function upsertEndpointTrustAnchor(
  scope: BoundEndpointScope,
  input: TrustAnchorInput,
  now?: Date,
): Promise<EndpointTrustAnchor> {
  const rows = await executorFor(scope)
    .insert(endpointTrustAnchors)
    .values({ ...input, endpointId: scope.endpointId })
    .onConflictDoUpdate({
      target: endpointTrustAnchors.endpointId,
      set: { ...input, updatedAt: nowValue(now) },
    })
    .returning();
  return requireRow(rows, "upsert into endpoint_trust_anchors");
}

/**
 * The scoped endpoint's trust anchor, if it has one.
 *
 * @param scope - The endpoint, bound to the transaction that declared its tenant.
 * @returns The rule, or undefined - which is the endpoint's answer that it
 *   accepts no registrations at all.
 */
export async function getEndpointTrustAnchor(
  scope: BoundEndpointScope,
): Promise<EndpointTrustAnchor | undefined> {
  return firstRow(
    await executorFor(scope)
      .select()
      .from(endpointTrustAnchors)
      .where(eq(endpointTrustAnchors.endpointId, scope.endpointId))
      .limit(1),
  );
}

/**
 * Removes the scoped endpoint's trust anchor, returning it to refusing
 * registration.
 *
 * The clients the anchor vouched for are deliberately untouched: each carries its
 * own expiry, and withdrawing the rule is a decision about future registrations
 * rather than about registrations already made.
 *
 * @param scope - The endpoint, bound to the transaction that declared its tenant.
 * @returns Whether a rule was removed.
 */
export async function deleteEndpointTrustAnchor(
  scope: BoundEndpointScope,
): Promise<boolean> {
  const rows = await executorFor(scope)
    .delete(endpointTrustAnchors)
    .where(eq(endpointTrustAnchors.endpointId, scope.endpointId))
    .returning({ endpointId: endpointTrustAnchors.endpointId });
  return rows.length > 0;
}

/**
 * Configures the scoped endpoint's ticket issuer, replacing any it already had.
 *
 * @param scope - The endpoint the rule belongs to, bound to the transaction that
 *   declared its tenant.
 * @param input - The issuer, its key address, the accepted ticket types and the
 *   lifetime cap. An input naming no ticket type configures an issuer whose every
 *   ticket is refused, which is the only safe reading of a rule that names none.
 * @param now - Stamps `updated_at`; defaults to the transaction clock.
 * @returns The stored rule.
 * @throws {Error} When the write returns no row.
 * @example
 * ```ts
 * await withTenantScope(db, endpointScope, (bound) =>
 *   upsertEndpointTicketIssuer(bound, {
 *     issuer: "https://tickets.example.org",
 *     jwksUri: "https://tickets.example.org/jwks",
 *     acceptedTicketTypes: ["patient-self-access"],
 *   }),
 * );
 * ```
 */
export async function upsertEndpointTicketIssuer(
  scope: BoundEndpointScope,
  input: TicketIssuerInput,
  now?: Date,
): Promise<EndpointTicketIssuer> {
  const rows = await executorFor(scope)
    .insert(endpointTicketIssuers)
    .values({ ...input, endpointId: scope.endpointId })
    .onConflictDoUpdate({
      target: endpointTicketIssuers.endpointId,
      set: { ...input, updatedAt: nowValue(now) },
    })
    .returning();
  return requireRow(rows, "upsert into endpoint_ticket_issuers");
}

/**
 * The scoped endpoint's ticket issuer, if it has one.
 *
 * @param scope - The endpoint, bound to the transaction that declared its tenant.
 * @returns The rule, or undefined - which is the endpoint's answer that token
 *   exchange is an unsupported grant type.
 */
export async function getEndpointTicketIssuer(
  scope: BoundEndpointScope,
): Promise<EndpointTicketIssuer | undefined> {
  return firstRow(
    await executorFor(scope)
      .select()
      .from(endpointTicketIssuers)
      .where(eq(endpointTicketIssuers.endpointId, scope.endpointId))
      .limit(1),
  );
}

/**
 * Removes the scoped endpoint's ticket issuer, returning it to refusing the
 * exchange grant.
 *
 * @param scope - The endpoint, bound to the transaction that declared its tenant.
 * @returns Whether a rule was removed.
 */
export async function deleteEndpointTicketIssuer(
  scope: BoundEndpointScope,
): Promise<boolean> {
  const rows = await executorFor(scope)
    .delete(endpointTicketIssuers)
    .where(eq(endpointTicketIssuers.endpointId, scope.endpointId))
    .returning({ endpointId: endpointTicketIssuers.endpointId });
  return rows.length > 0;
}
