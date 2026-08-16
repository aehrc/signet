/**
 * What an exchanged token is allowed to carry, and for how long.
 *
 * An exchanged access token grants the overlap of three things: what the client
 * asked for, what the ticket permits, and what the endpoint's policy grants that
 * client. The first two meet here; the third is `evaluatePolicy`, which runs over
 * this module's result, because the policy is the only thing that can translate a
 * scope into the claims a resource server reads and there must not be a second
 * implementation of that.
 *
 * The client's own allowlist is met here too. It is the per-client ceiling an
 * operator edits, and it is checked for the same reason the `client_credentials`
 * grant checks it: neither grant visits `/authorize`, where an interactive
 * client's request is held inside its allowlist. Without it, a ticket could hand a
 * client access its registration never permitted it to ask for.
 *
 * **An intersection, not a filter.** A client asking for `patient/Patient.cruds`
 * against a ticket permitting `patient/Patient.rs` is granted the reads. Dropping
 * the whole scope because it asked for more would hand a correctly ticketed app no
 * access at all, which fails opaquely at its first API call; granting what it
 * asked for would ignore the ticket. The overlap is the only answer that is both
 * useful and bounded, and it is the same reduction the policy engine performs when
 * a grant rule narrows.
 *
 * **No refresh scope survives.** The ticket's remaining validity is one of the
 * ceilings on the exchanged token, and a refresh token outliving the ticket would
 * be a way around it. So a refresh scope is dropped here rather than refused: what
 * the client is told is the scope it actually got.
 *
 * **An empty overlap refuses.** A scopeless token is worse than a refusal, because
 * the app believes it was authorised and finds out otherwise at its first request.
 *
 * Author: John Grimes
 */

import { formatScope } from "../scopes/serialise.js";
import { PERMISSION_ORDER } from "../scopes/types.js";

import type {
  Permission,
  ResourceScope,
  Scope,
  ScopeParameter,
} from "../scopes/types.js";

/** Why an intersection granted nothing. */
export type TicketScopeRefusal =
  /** The request named no scopes, so there was nothing to bound. */
  | "nothing-requested"
  /** The three sides have nothing in common. */
  | "no-overlap";

/** The sides an exchanged token's scopes are bounded by. */
export interface TicketScopeSides {
  /** What the client asked for, parsed. */
  readonly requested: readonly Scope[];
  /** The ticket's `smart_scopes`, parsed. */
  readonly ticketScopes: readonly Scope[];
  /** The client's registered allowlist, parsed. */
  readonly clientAllowlist: readonly Scope[];
}

/** The outcome of intersecting the sides. */
export type TicketScopeResult =
  | { readonly ok: true; readonly scopes: readonly Scope[] }
  | {
      readonly ok: false;
      readonly code: TicketScopeRefusal;
      readonly description: string;
    };

/** The ceilings an exchanged access token's lifetime is bounded by. */
export interface ExchangedTokenCeilings {
  /** Seconds until the ticket expires. */
  readonly ticketRemainingSeconds: number;
  /** The ticket issuer rule's cap, in seconds. */
  readonly ruleMaxLifetimeSeconds: number;
}

/** The permissions two resource scopes share, in canonical order. */
function sharedPermissions(
  a: readonly Permission[],
  b: readonly Permission[],
): readonly Permission[] {
  const other = new Set<Permission>(b);
  return PERMISSION_ORDER.filter(
    (permission) => a.includes(permission) && other.has(permission),
  );
}

/**
 * Every restriction either side names.
 *
 * A search restriction only ever narrows access, so the union is the intersection
 * of what the two scopes permit: a scope limited to `category=laboratory` and one
 * that is not meet at the limited one.
 */
function mergedParameters(
  a: readonly ScopeParameter[],
  b: readonly ScopeParameter[],
): readonly ScopeParameter[] {
  const merged = [...a];
  for (const parameter of b) {
    const present = merged.some(
      (entry) =>
        entry.name === parameter.name && entry.value === parameter.value,
    );
    if (!present) {
      merged.push(parameter);
    }
  }
  return merged;
}

/**
 * The resource type two scopes agree on.
 *
 * A wildcard on either side resolves to whatever the other names, which is what
 * makes `patient/*.rs` against a ticket permitting `patient/Patient.rs` grant the
 * Patient reads rather than nothing.
 */
function sharedResourceType(a: string, b: string): string | undefined {
  if (a === "*") {
    return b;
  }
  if (b === "*") {
    return a;
  }
  return a === b ? a : undefined;
}

/** The access two resource scopes both permit, or undefined for none. */
function intersectResourceScopes(
  a: ResourceScope,
  b: ResourceScope,
): ResourceScope | undefined {
  if (a.context !== b.context) {
    return undefined;
  }
  const resourceType = sharedResourceType(a.resourceType, b.resourceType);
  if (resourceType === undefined) {
    return undefined;
  }
  const permissions = sharedPermissions(a.permissions, b.permissions);
  if (permissions.length === 0) {
    return undefined;
  }
  return {
    kind: "resource",
    context: a.context,
    resourceType,
    permissions,
    parameters: mergedParameters(a.parameters, b.parameters),
  };
}

/**
 * The access two scopes both permit.
 *
 * Resource scopes meet field by field. Everything else - launch, identity,
 * refresh and custom scopes - has no internal structure to reduce, so the only
 * intersection is equality, compared on the canonical string form so that two
 * spellings of the same scope do not read as different scopes.
 */
function intersectScopes(a: Scope, b: Scope): Scope | undefined {
  if (a.kind === "resource" && b.kind === "resource") {
    return intersectResourceScopes(a, b);
  }
  return formatScope(a) === formatScope(b) ? a : undefined;
}

/** Every scope both sets permit, deduplicated, in the first set's order. */
function intersectScopeSets(
  candidates: readonly Scope[],
  ceiling: readonly Scope[],
): readonly Scope[] {
  const kept: Scope[] = [];
  const seen = new Set<string>();
  for (const candidate of candidates) {
    for (const bound of ceiling) {
      const overlap = intersectScopes(candidate, bound);
      if (overlap === undefined) {
        continue;
      }
      const key = formatScope(overlap);
      if (!seen.has(key)) {
        seen.add(key);
        kept.push(overlap);
      }
    }
  }
  return kept;
}

/**
 * Intersects what was requested with what the ticket and the client permit.
 *
 * Two of the three sides an exchanged token is bounded by. The third is the
 * endpoint's policy, which the issuance chokepoint evaluates over this result -
 * so a scope the policy refuses is not granted however clearly the ticket
 * permitted it, and there is no second implementation of what a policy grants.
 *
 * @param sides - The requested scopes, the ticket's, and the client's allowlist.
 * @returns The scopes to ask the policy for, or why nothing is left to ask for.
 * @example
 * ```ts
 * const overlap = intersectTicketScopes({
 *   requested: parseScopes(requested).scopes,
 *   ticketScopes: ticket.scopes,
 *   clientAllowlist: parseScopes(client.allowedScopes.join(" ")).scopes,
 * });
 * if (!overlap.ok) {
 *   return grantRefusal("invalid_scope", overlap.description);
 * }
 * ```
 */
export function intersectTicketScopes(
  sides: TicketScopeSides,
): TicketScopeResult {
  if (sides.requested.length === 0) {
    return {
      ok: false,
      code: "nothing-requested",
      description: "scope is required for a permission ticket exchange",
    };
  }

  const bounded = intersectScopeSets(
    intersectScopeSets(sides.requested, sides.ticketScopes),
    sides.clientAllowlist,
  );
  // Dropped rather than refused: no refresh token is issued for this grant, so a
  // refresh scope would be reported as granted and then honoured by nothing.
  const scopes = bounded.filter((scope) => scope.kind !== "refresh");

  return scopes.length === 0
    ? {
        ok: false,
        code: "no-overlap",
        description:
          "The permission ticket, the requested scopes and this client's registration have no access in common",
      }
    : { ok: true, scopes };
}

/**
 * The longest an exchanged access token may live.
 *
 * The third ceiling - the endpoint's own access token lifetime, which comes from
 * its policy - is applied by the issuance chokepoint, the only place that has read
 * the policy. The token therefore expires at the earliest of all three.
 *
 * @param ceilings - The ticket's remaining validity and the rule's cap.
 * @returns Seconds, never negative. Zero means the ticket lapsed between
 *   validation and issuance, and the caller must refuse rather than mint a token
 *   that has already expired.
 * @example
 * ```ts
 * const ceiling = capExchangedTokenLifetime({
 *   ticketRemainingSeconds: Math.floor((ticket.expiresAt.getTime() - now.getTime()) / 1000),
 *   ruleMaxLifetimeSeconds: rule.maxTokenLifetimeSecs,
 * });
 * ```
 */
export function capExchangedTokenLifetime(
  ceilings: ExchangedTokenCeilings,
): number {
  return Math.max(
    0,
    Math.min(ceilings.ticketRemainingSeconds, ceilings.ruleMaxLifetimeSeconds),
  );
}
