/**
 * Mapping an upstream provider's claims onto Signet's user model.
 *
 * This is the part of federation an operator actually configures, and the part
 * that decides what a federated person can do: `fhirUser` becomes the identity a
 * policy templates into tokens, and `roles` becomes what a policy tests. Getting
 * it wrong is not a cosmetic problem, so the mapping is deliberately literal —
 * it copies named claims and does nothing clever.
 *
 * What it will not do is invent a value. A mapping naming a claim the provider
 * did not send yields nothing, rather than an empty string or a null; the caller
 * sees a field it did not get and can decide whether that is fatal. A `fhirUser`
 * of `""` would sail through a policy that only checks for presence.
 *
 * Roles arrive in two shapes in the wild - a JSON array, and a space-delimited
 * string, the latter because some providers model roles as OAuth scopes - so both
 * are accepted. Nothing else is: a roles claim that is a number is a
 * misconfiguration, and silently stringifying it would produce a role named
 * `[object Object]` that an operator would then have to write a policy against.
 *
 * Attributes are copied verbatim, but only from the claims the operator named.
 * An upstream provider can put anything in a token, and copying the lot would
 * make every unrecognised claim available to a policy template - and from there
 * into a signed access token that a downstream FHIR server reads.
 */

/** Which upstream claims populate which Signet fields. */
export interface ClaimMappings {
  /** Claim yielding a relative FHIR reference, e.g. `Practitioner/123`. */
  readonly fhirUser?: string;
  /** Claim yielding roles, as an array or a space-delimited string. */
  readonly roles?: string;
  readonly displayName?: string;
  /** Further claims copied verbatim into the user's attributes. */
  readonly attributes?: readonly string[];
}

/** What a mapping produced from one set of upstream claims. */
export interface MappedIdentity {
  /** Absent when the mapping named no claim, or the provider sent none. */
  readonly fhirUser?: string;
  readonly displayName?: string;
  readonly roles: readonly string[];
  readonly attributes: Readonly<Record<string, unknown>>;
}

/** Reads a claim expected to be a non-empty string. */
function stringClaim(
  claims: Readonly<Record<string, unknown>>,
  name: string | undefined,
): string | undefined {
  if (name === undefined) {
    return undefined;
  }
  const value = claims[name];
  return typeof value === "string" && value.trim().length > 0
    ? value.trim()
    : undefined;
}

/** Splits a space-delimited roles claim, or yields nothing for any other type. */
function rolesFromString(value: unknown): readonly string[] {
  return typeof value === "string" ? value.split(/\s+/) : [];
}

/**
 * Reads a roles claim in either of the two shapes providers use.
 *
 * Deduplicated, order preserved, blanks dropped. Order is preserved because a
 * policy may reasonably treat the first role as the primary one, and reordering
 * a list the provider chose would be this module deciding something it has no
 * business deciding.
 *
 * @param claims - The upstream claims.
 * @param name - The claim the operator named, if any.
 */
export function readRoles(
  claims: Readonly<Record<string, unknown>>,
  name: string | undefined,
): readonly string[] {
  if (name === undefined) {
    return [];
  }
  const value = claims[name];
  const raw: readonly unknown[] = Array.isArray(value)
    ? value
    : rolesFromString(value);

  const roles: string[] = [];
  for (const entry of raw) {
    if (typeof entry !== "string") {
      continue;
    }
    const trimmed = entry.trim();
    if (trimmed.length > 0 && !roles.includes(trimmed)) {
      roles.push(trimmed);
    }
  }
  return roles;
}

/**
 * Maps upstream claims onto the fields Signet stores for an end user.
 *
 * @param mappings - What the operator configured.
 * @param claims - The ID token claims merged with the userinfo response.
 */
export function mapUpstreamClaims(
  mappings: ClaimMappings,
  claims: Readonly<Record<string, unknown>>,
): MappedIdentity {
  const attributes: Record<string, unknown> = {};
  for (const name of mappings.attributes ?? []) {
    const value = claims[name];
    // `undefined` is not a JSON value, so a claim that is absent is absent -
    // storing the key with an undefined value would round-trip through the
    // database as null and read, to a policy, as a value that was sent.
    if (value !== undefined) {
      attributes[name] = value;
    }
  }

  const fhirUser = stringClaim(claims, mappings.fhirUser);
  const displayName = stringClaim(claims, mappings.displayName);

  return {
    ...(fhirUser === undefined ? {} : { fhirUser }),
    ...(displayName === undefined ? {} : { displayName }),
    roles: readRoles(claims, mappings.roles),
    attributes,
  };
}

/**
 * Merges an ID token's claims with a userinfo response.
 *
 * Userinfo wins, because it is the fresher document and the one a provider
 * updates when a person's details change - an ID token is a snapshot taken at
 * sign-in and providers routinely keep it thin.
 *
 * The exception is `sub`, which is never taken from userinfo. Core §5.3.2 says a
 * userinfo `sub` that does not match the ID token's must cause the response to be
 * rejected outright; the caller does that check, and this function keeps the ID
 * token's value so that a merge cannot quietly rewrite the identity even if the
 * check were ever removed.
 *
 * @param idTokenClaims - The verified ID token's claims.
 * @param userinfoClaims - The userinfo response, if one was fetched.
 */
export function mergeClaims(
  idTokenClaims: Readonly<Record<string, unknown>>,
  userinfoClaims: Readonly<Record<string, unknown>> | undefined,
): Readonly<Record<string, unknown>> {
  if (userinfoClaims === undefined) {
    return idTokenClaims;
  }
  return { ...idTokenClaims, ...userinfoClaims, sub: idTokenClaims["sub"] };
}

/**
 * The local username a federated person is provisioned under.
 *
 * Namespaced by issuer, because usernames are unique per endpoint and two
 * providers can both have a user `12345`. Built from `sub` rather than from an
 * email or a preferred username: those change, and a person whose email changed
 * would come back as a different account with none of their consents.
 *
 * The result is not a credential and is never used to authenticate - it exists so
 * that the second sign-in finds the row the first one created.
 *
 * @param issuer - The provider's issuer identifier.
 * @param subject - The provider's `sub` for this person.
 */
export function federatedUsername(issuer: string, subject: string): string {
  return `${issuer}#${subject}`;
}
