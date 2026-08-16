/**
 * The two rules that turn vouched registration and ticket exchange on.
 *
 * Signet refuses dynamic client registration and token exchange everywhere by
 * default, and these tables are the only thing that changes that - per endpoint,
 * by an explicit rule naming who is trusted. An endpoint with no row here answers
 * 404 at its registration route and `unsupported_grant_type` at its token
 * endpoint, and advertises neither. That is the deny-by-default posture the
 * constitution's first principle requires: capability arrives by adding a rule,
 * never by removing a restriction.
 *
 * `endpoint_id` is the primary key of both, rather than a surrogate key with a
 * unique index beside it. An endpoint trusts at most one anchor and at most one
 * ticket issuer, and making that structural means "which of these two rules
 * applies?" is not a question any code can be written to answer wrongly. It is
 * the same shape `idp_configs` uses, for the same reason.
 *
 * Neither table holds key material. Both hold a `jwks_uri` that is fetched fresh
 * through the outbound guard - the address is supplied by an endpoint
 * administrator rather than by the deployment's operator, and a key cached in the
 * database would let a withdrawn key keep verifying for as long as nobody
 * noticed.
 *
 * Author: John Grimes
 */

import { integer, pgTable, text, uuid } from "drizzle-orm/pg-core";

import { timestamps } from "./columns.js";
import { endpoints } from "./endpoints.js";

/**
 * What both rules say: which endpoint, whom it trusts, and where the keys are.
 *
 * A factory rather than a shared object, in step with `./columns.ts`: a Drizzle
 * column builder carries the name it was constructed with, so handing the same
 * one to two tables invites an aliasing bug that only shows up in generated DDL.
 *
 * `endpoint_id` is the primary key as well as the foreign key. An endpoint names
 * at most one anchor and at most one ticket issuer, and making that structural
 * removes the need to police it in application code - a second rule is not a row
 * anything has to choose between, it is a row that cannot exist.
 *
 * `jwks_uri` is administrator-supplied, so every fetch of it goes through the
 * SSRF guard that blocks private and link-local ranges, and a failed fetch
 * refuses the operation rather than falling back to anything.
 */
function trustedIssuer() {
  return {
    endpointId: uuid("endpoint_id")
      .primaryKey()
      .references(() => endpoints.id, { onDelete: "cascade" }),
    /** The issuer identifier, matched against a presented token's `iss`. */
    issuer: text("issuer").notNull(),
    /** Where that issuer publishes its keys. Fetched through the guard, never cached here. */
    jwksUri: text("jwks_uri").notNull(),
  };
}

/**
 * The anchor whose software statements this endpoint accepts registrations from.
 *
 * Its presence is the whole of the endpoint's registration policy: the statement
 * must be signed by a key this issuer currently publishes, must name this issuer,
 * and must not vouch for longer than `max_vouching_days` allows.
 */
export const endpointTrustAnchors = pgTable("endpoint_trust_anchors", {
  ...trustedIssuer(),
  /**
   * The longest vouching this endpoint will honour, in days.
   *
   * The endpoint's ceiling, not the anchor's: a statement claiming a longer
   * validity than this is refused rather than silently shortened, because a
   * registration capped without the anchor's knowledge is no longer the
   * registration the anchor vouched for.
   */
  maxVouchingDays: integer("max_vouching_days").notNull().default(30),
  ...timestamps(),
});

/**
 * The issuer whose permission tickets this endpoint accepts at its token
 * endpoint.
 */
export const endpointTicketIssuers = pgTable("endpoint_ticket_issuers", {
  ...trustedIssuer(),
  /**
   * The ticket types this endpoint honours, and the list discovery advertises.
   *
   * Defaults to empty, which refuses every ticket. A rule that exists but names
   * no type is a rule that grants nothing - the alternative default, "all types",
   * would make a half-configured endpoint accept ticket types nobody chose.
   *
   * A Postgres array rather than a delimited string so that "does this endpoint
   * accept this type?" is a containment query rather than a substring match.
   */
  acceptedTicketTypes: text("accepted_ticket_types")
    .array()
    .notNull()
    .default([]),
  /**
   * The ceiling on an exchanged access token's lifetime, in seconds.
   *
   * One of three: the granted token expires at the earliest of the ticket's
   * remaining validity, the endpoint's own access token TTL, and this.
   */
  maxTokenLifetimeSecs: integer("max_token_lifetime_secs")
    .notNull()
    .default(300),
  ...timestamps(),
});

/** A trust anchor rule as selected. */
export type EndpointTrustAnchor = typeof endpointTrustAnchors.$inferSelect;
/** Values required to insert a trust anchor rule. */
export type NewEndpointTrustAnchor = typeof endpointTrustAnchors.$inferInsert;

/** A ticket issuer rule as selected. */
export type EndpointTicketIssuer = typeof endpointTicketIssuers.$inferSelect;
/** Values required to insert a ticket issuer rule. */
export type NewEndpointTicketIssuer = typeof endpointTicketIssuers.$inferInsert;
