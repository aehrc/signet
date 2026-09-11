/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * What a vouched registration is allowed to be, decided without touching anything.
 *
 * A registration endpoint that accepts a trust anchor's software statements makes
 * three judgements, and none of them needs a database, a socket or a key: whether
 * the request is a registration request at all, whether the statement's claims
 * entitle it to register here, and whether the metadata the anchor sealed inside
 * describes a client Signet can actually operate. Each is here, as a function over
 * data the route has already fetched, so the console's view of a vouched client and
 * the endpoint that created it cannot disagree about what "vouched" means.
 *
 * Two rules shape everything below.
 *
 * **The metadata is the anchor's, entirely.** {@link parseRegistrationBody} refuses
 * a body carrying anything beside the statement rather than ignoring it. Ignoring
 * would be safe today and a merge waiting to be written tomorrow, and a merged
 * redirect URI is a client the anchor never vouched for.
 *
 * **Absence is never permission.** A statement that omits its expiry vouches
 * forever, one that omits its authentication method would take RFC 7591's
 * `client_secret_basic` default, and one that omits its grant types would take the
 * `authorization_code` default. All three are refused: the defaults exist to make a
 * registration request short, and this is not a request, it is a credential.
 *
 * Author: John Grimes
 */

import {
  isCompactJws,
  isJsonObject,
  PERMITTED_TRUST_ALGORITHMS,
  readTrustedTokenEnvelope,
  textClaim,
} from "../trust/claims.js";
import { isScriptFreeUri } from "../uris.js";

/**
 * How far a statement's `iat` may run ahead of Signet's clock, in seconds.
 *
 * The same tolerance every token a trusted issuer signs is judged by.
 */
export { TRUST_CLOCK_TOLERANCE_SECONDS as STATEMENT_CLOCK_TOLERANCE_SECONDS } from "../trust/claims.js";

import type { ClientType, GrantType } from "../policy/types.js";
import type { TrustedTokenRefusal } from "../trust/claims.js";

/**
 * The signature algorithms a software statement may be signed with.
 *
 * The same closed asymmetric list every token a trusted issuer signs is held to -
 * see `../trust/claims.ts`. Named here as well because a caller verifying a
 * statement should not have to know that it shares the list with a permission
 * ticket, and because the two could diverge later without the callers changing.
 */
export const PERMITTED_STATEMENT_ALGORITHMS: readonly string[] =
  PERMITTED_TRUST_ALGORITHMS;

/** The most redirect URIs one registration may carry. */
const MAX_REDIRECT_URIS = 20;

/** Seconds in a day, for the vouching ceiling. */
const SECONDS_PER_DAY = 86_400;

/** Why a registration request body was refused. */
export type RegistrationBodyRefusal =
  /** The body is not a JSON object. */
  | "not-an-object"
  /** No `software_statement`, or it is not a string. */
  | "missing-statement"
  /** Present, but not a three-part compact JWS. */
  | "malformed-statement"
  /** Carried client metadata beside the statement. */
  | "metadata-outside-statement";

/** The outcome of reading a registration request body. */
export type RegistrationBodyResult =
  | { readonly ok: true; readonly softwareStatement: string }
  | {
      readonly ok: false;
      readonly code: RegistrationBodyRefusal;
      readonly description: string;
    };

/** Builds a refusal of the request body. */
function refuseBody(
  code: RegistrationBodyRefusal,
  description: string,
): RegistrationBodyResult {
  return { ok: false, code, description };
}

/** Whether a value is a JSON object rather than an array, null or a scalar. */
const isObject = isJsonObject;

/** A non-empty string, or undefined for anything else. */
const text = textClaim;

/**
 * Reads a registration request body.
 *
 * @param body - The parsed JSON the request carried. Untrusted.
 * @returns The compact statement to verify, or why the body was refused.
 * @example
 * ```ts
 * const parsed = parseRegistrationBody(await c.req.json());
 * if (!parsed.ok) {
 *   return refuse("invalid_request", parsed.description);
 * }
 * ```
 */
export function parseRegistrationBody(body: unknown): RegistrationBodyResult {
  if (!isObject(body)) {
    return refuseBody(
      "not-an-object",
      "A registration request is a JSON object carrying a software_statement",
    );
  }

  const statement = text(body["software_statement"]);
  if (statement === undefined) {
    return refuseBody(
      "missing-statement",
      "This endpoint registers clients only from a software_statement signed by its trust anchor",
    );
  }
  if (!isCompactJws(statement)) {
    return refuseBody(
      "malformed-statement",
      "software_statement is not a compact JWS",
    );
  }

  const extra = Object.keys(body).filter((key) => key !== "software_statement");
  if (extra.length > 0) {
    return refuseBody(
      "metadata-outside-statement",
      `The statement is the only metadata this endpoint reads; remove ${extra.join(", ")}`,
    );
  }

  return { ok: true, softwareStatement: statement };
}

/** Why a software statement was refused. */
export type StatementRefusal =
  /** The verified payload is not a JSON object. */
  | "not-an-object"
  /** `iss` is absent, or is not the anchor the endpoint's rule names. */
  | "issuer-mismatch"
  /** No `jti`, so the statement could never be spent. */
  | "missing-statement-id"
  /** No `iat`. */
  | "missing-issued-at"
  /** No `exp`, which would vouch indefinitely. */
  | "missing-expiry"
  /** `exp` has passed. */
  | "expired"
  /** `iat` is ahead of Signet's clock by more than the tolerance. */
  | "issued-in-the-future"
  /** `exp` is beyond the endpoint's configured maximum vouching lifetime. */
  | "vouching-too-long";

/** What a valid statement vouches for. */
export interface VouchedStatement {
  /** The anchor's issuer identifier, as recorded on the client. */
  readonly issuer: string;
  /** The statement's `jti`, which one endpoint honours exactly once. */
  readonly statementId: string;
  readonly issuedAt: Date;
  /** When the vouching lapses, after which no grant type issues a token. */
  readonly expiresAt: Date;
}

/** What one statement validation is about. */
export interface StatementCheck {
  /** The statement's claims, as decoded from a payload whose signature verified. */
  readonly claims: unknown;
  /** The issuer the endpoint's trust anchor rule names. */
  readonly anchorIssuer: string;
  /** The endpoint's ceiling on how long a statement may vouch for. */
  readonly maxVouchingDays: number;
  /** The instant the temporal claims are judged against. */
  readonly now: Date;
}

/** The outcome of validating a statement's claims. */
export type StatementValidation =
  | { readonly ok: true; readonly statement: VouchedStatement }
  | {
      readonly ok: false;
      readonly code: StatementRefusal;
      readonly description: string;
    };

/** Builds a refusal of the statement. */
function refuseStatement(
  code: StatementRefusal,
  description: string,
): StatementValidation {
  return { ok: false, code, description };
}

/**
 * How the shared envelope's refusals read as a registration's refusals.
 *
 * A total record, so an envelope refusal that is added later cannot be silently
 * dropped here. Only one of them is renamed, and the rename is the point: a
 * statement's `jti` is what records it as spent, so "no jti" means "this could
 * never be spent" rather than the generic "no identifier".
 */
const STATEMENT_REFUSAL_FOR: Readonly<
  Record<TrustedTokenRefusal, StatementRefusal>
> = {
  "not-an-object": "not-an-object",
  "issuer-mismatch": "issuer-mismatch",
  "missing-token-id": "missing-statement-id",
  "missing-issued-at": "missing-issued-at",
  "missing-expiry": "missing-expiry",
  expired: "expired",
  "issued-in-the-future": "issued-in-the-future",
};

/**
 * Validates a statement's claims against the endpoint's trust anchor rule.
 *
 * The signature is not checked here and cannot be: verifying it needs the anchor's
 * published keys, which is a fetch. The caller verifies first and passes the
 * decoded payload, so every refusal this function gives is about what the anchor
 * said rather than about whether the anchor said it.
 *
 * @param check - The claims, the anchor the rule names, the endpoint's vouching
 *   ceiling, and the instant to judge against.
 * @returns What the statement vouches for, or why it was refused. Each refusal has
 *   its own code, because the endpoint has to be able to tell an app whose statement
 *   expired apart from one whose anchor is not this endpoint's.
 * @example
 * ```ts
 * const validated = validateSoftwareStatement({
 *   claims,
 *   anchorIssuer: anchor.issuer,
 *   maxVouchingDays: anchor.maxVouchingDays,
 *   now: context.clock(),
 * });
 * ```
 */
export function validateSoftwareStatement(
  check: StatementCheck,
): StatementValidation {
  const { now } = check;
  const read = readTrustedTokenEnvelope({
    claims: check.claims,
    expectedIssuer: check.anchorIssuer,
    now,
    noun: "software statement",
  });
  if (!read.ok) {
    return refuseStatement(STATEMENT_REFUSAL_FOR[read.code], read.description);
  }
  const envelope = read.envelope;

  // The endpoint's ceiling, measured from now rather than from `iat`: what is being
  // bounded is how long this registration may live, and it starts now.
  const nowSeconds = Math.floor(now.getTime() / 1000);
  const ceiling = nowSeconds + check.maxVouchingDays * SECONDS_PER_DAY;
  if (Math.floor(envelope.expiresAt.getTime() / 1000) > ceiling) {
    return refuseStatement(
      "vouching-too-long",
      `This endpoint vouches for no longer than ${String(check.maxVouchingDays)} days`,
    );
  }

  return {
    ok: true,
    statement: {
      issuer: envelope.issuer,
      statementId: envelope.tokenId,
      issuedAt: envelope.issuedAt,
      expiresAt: envelope.expiresAt,
    },
  };
}

/** Why a statement's client metadata was refused. */
export type ClientMetadataRefusal =
  | "not-an-object"
  | "missing-name"
  /** An interactive client with nowhere to send the code. */
  | "missing-redirect-uris"
  | "malformed-redirect-uri"
  /** A scheme the browser executes rather than navigates to. */
  | "unsafe-redirect-uri"
  | "too-many-redirect-uris"
  /** Absent, empty, or naming a grant Signet does not issue. */
  | "unsupported-grant-type"
  /** Absent, or naming a credential posture Signet does not accept. */
  | "unsupported-auth-method"
  /** `private_key_jwt` with neither `jwks` nor `jwks_uri`. */
  | "missing-keys"
  /** Both `jwks` and `jwks_uri`, so no single key verified an assertion. */
  | "conflicting-keys"
  /** Keys offered by a client that does not authenticate with them. */
  | "unexpected-keys";

/** The client a statement describes, in Signet's own vocabulary. */
export interface VouchedClientMetadata {
  readonly name: string;
  readonly clientType: ClientType;
  readonly redirectUris: readonly string[];
  readonly grantTypes: readonly GrantType[];
  /** The client's allowlist ceiling; the endpoint's policy narrows further. */
  readonly scopes: readonly string[];
  readonly logoUri?: string;
  readonly contactEmail?: string;
  readonly jwks?: Readonly<Record<string, unknown>>;
  readonly jwksUri?: string;
}

/** The outcome of reading a statement's client metadata. */
export type ClientMetadataValidation =
  | { readonly ok: true; readonly metadata: VouchedClientMetadata }
  | {
      readonly ok: false;
      readonly code: ClientMetadataRefusal;
      readonly description: string;
    };

/** Builds a refusal of the metadata. */
function refuseMetadata(
  code: ClientMetadataRefusal,
  description: string,
): ClientMetadataValidation {
  return { ok: false, code, description };
}

/**
 * How each RFC 7591 authentication method maps onto a Signet client type.
 *
 * A total record over what is accepted, so the accepted set and the mapping are
 * the same thing. `client_secret_jwt` is absent deliberately: Signet verifies
 * asymmetric assertions only.
 */
const CLIENT_TYPE_FOR_AUTH_METHOD: Readonly<Record<string, ClientType>> = {
  none: "public",
  client_secret_basic: "confidential-symmetric",
  client_secret_post: "confidential-symmetric",
  private_key_jwt: "confidential-asymmetric",
};

/** The grants Signet issues tokens for, as a statement may name them. */
const SUPPORTED_GRANT_TYPES: readonly GrantType[] = [
  "authorization_code",
  "client_credentials",
  "refresh_token",
];

/** Whether every entry is a grant Signet issues. */
function asGrantTypes(value: unknown): readonly GrantType[] | undefined {
  if (!Array.isArray(value) || value.length === 0) {
    return undefined;
  }
  const grants = value.filter((entry): entry is GrantType =>
    SUPPORTED_GRANT_TYPES.includes(entry as GrantType),
  );
  return grants.length === value.length ? grants : undefined;
}

/** Whether a redirect URI is absolute, as `/authorize` will require. */
function isAbsoluteUri(value: string): boolean {
  return URL.canParse(value);
}

/** The strings in an array claim, ignoring anything else in it. */
function textArray(value: unknown): readonly string[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string")
    : [];
}

/**
 * Checks the redirect URIs a statement carries against the grants it asks for.
 *
 * Returns the refusal rather than a boolean so the caller can say which rule was
 * broken: "no redirect URI" and "a redirect URI that is not a URL" are different
 * mistakes on the anchor's part.
 */
function checkRedirectUris(
  redirectUris: readonly string[],
  grantTypes: readonly GrantType[],
): ClientMetadataValidation | undefined {
  if (redirectUris.length === 0) {
    // A backend service never visits `/authorize`, so it has nothing to redirect
    // to; anything interactive does.
    return grantTypes.includes("authorization_code")
      ? refuseMetadata(
          "missing-redirect-uris",
          "A statement registering an authorization_code client must carry at least one redirect_uri",
        )
      : undefined;
  }
  if (redirectUris.length > MAX_REDIRECT_URIS) {
    return refuseMetadata(
      "too-many-redirect-uris",
      `A registration carries at most ${String(MAX_REDIRECT_URIS)} redirect URIs`,
    );
  }
  const malformed = redirectUris.find((uri) => !isAbsoluteUri(uri));
  if (malformed !== undefined) {
    return refuseMetadata(
      "malformed-redirect-uri",
      `redirect_uri ${malformed} is not an absolute URL, so it could never be matched`,
    );
  }
  const unsafe = redirectUris.find((uri) => !isScriptFreeUri(uri));
  return unsafe === undefined
    ? undefined
    : refuseMetadata(
        "unsafe-redirect-uri",
        `redirect_uri ${unsafe} names a scheme the browser executes rather than navigates to`,
      );
}

/**
 * Checks the key material a statement offers against the client type presenting it.
 *
 * The anchor vouches for the metadata's origin rather than its coherence, so a
 * statement offering keys to a public client is refused rather than silently
 * stripped - the anchor would otherwise believe it had vouched for a client that
 * verifies assertions when it does not.
 */
function checkKeys(
  clientType: ClientType,
  jwks: unknown,
  jwksUri: string | undefined,
): ClientMetadataValidation | undefined {
  const hasJwks = isObject(jwks);
  if (hasJwks && jwksUri !== undefined) {
    return refuseMetadata(
      "conflicting-keys",
      "A statement offers either jwks or jwks_uri: with both there is no single answer to which key verified an assertion",
    );
  }
  if (clientType === "confidential-asymmetric") {
    return hasJwks || jwksUri !== undefined
      ? undefined
      : refuseMetadata(
          "missing-keys",
          "A private_key_jwt client needs jwks or jwks_uri to verify its assertions against",
        );
  }
  return hasJwks || jwksUri !== undefined
    ? refuseMetadata(
        "unexpected-keys",
        `A ${clientType} client does not authenticate with keys, so the statement's key material would be discarded`,
      )
    : undefined;
}

/**
 * Reads the client a statement describes, in the terms Signet registers clients in.
 *
 * @param claims - The statement's claims, whose signature has already verified.
 * @returns The metadata to register, or why it describes a client Signet will not
 *   operate. Everything returned comes from the statement; nothing is defaulted
 *   into existence.
 * @example
 * ```ts
 * const metadata = extractVouchedClientMetadata(claims);
 * if (!metadata.ok) {
 *   return refuse("invalid_client_metadata", metadata.description);
 * }
 * ```
 */
export function extractVouchedClientMetadata(
  claims: unknown,
): ClientMetadataValidation {
  if (!isObject(claims)) {
    return refuseMetadata(
      "not-an-object",
      "The software statement's payload is not a JSON object",
    );
  }

  const name = text(claims["client_name"]);
  if (name === undefined) {
    return refuseMetadata(
      "missing-name",
      "The software statement has no client_name",
    );
  }

  const method = text(claims["token_endpoint_auth_method"]) ?? "";
  const clientType = CLIENT_TYPE_FOR_AUTH_METHOD[method];
  if (clientType === undefined) {
    return refuseMetadata(
      "unsupported-auth-method",
      `token_endpoint_auth_method must be one of ${Object.keys(CLIENT_TYPE_FOR_AUTH_METHOD).join(", ")}`,
    );
  }

  const grantTypes = asGrantTypes(claims["grant_types"]);
  if (grantTypes === undefined) {
    return refuseMetadata(
      "unsupported-grant-type",
      `grant_types must name one or more of ${SUPPORTED_GRANT_TYPES.join(", ")}`,
    );
  }

  const redirectUris = textArray(claims["redirect_uris"]);
  const redirectRefusal = checkRedirectUris(redirectUris, grantTypes);
  if (redirectRefusal !== undefined) {
    return redirectRefusal;
  }

  const jwks = claims["jwks"];
  const jwksUri = text(claims["jwks_uri"]);
  const keyRefusal = checkKeys(clientType, jwks, jwksUri);
  if (keyRefusal !== undefined) {
    return keyRefusal;
  }

  const logoUri = text(claims["logo_uri"]);
  const contactEmail = textArray(claims["contacts"])[0];
  const scope = text(claims["scope"]);

  return {
    ok: true,
    metadata: {
      name,
      clientType,
      redirectUris,
      grantTypes,
      // Absent means none. The alternative reading - "every scope" - would have a
      // statement that forgot the field register a client with no ceiling at all.
      scopes: scope === undefined ? [] : scope.split(/\s+/u).filter(Boolean),
      ...(logoUri === undefined ? {} : { logoUri }),
      ...(contactEmail === undefined ? {} : { contactEmail }),
      ...(isObject(jwks) ? { jwks } : {}),
      ...(jwksUri === undefined ? {} : { jwksUri }),
    },
  };
}

/** Where a client's vouching stands. */
export interface VouchingState {
  /** Whether the client was created by an anchor at all. */
  readonly vouched: boolean;
  /** Whether the vouching has lapsed, after which every grant type refuses. */
  readonly expired: boolean;
  /** Seconds until it lapses. Zero once it has. */
  readonly secondsRemaining: number;
  /** Whole days until it lapses, rounded down. */
  readonly daysRemaining: number;
}

/**
 * Describes where a client's vouching stands.
 *
 * Used in two places that must agree: the issuance chokepoint, which refuses every
 * grant type once the vouching has lapsed, and the console's client detail, which
 * says so. A second implementation of the comparison would eventually disagree with
 * the first, and the visible symptom would be a console showing a live client that
 * cannot obtain a token.
 *
 * @param expiresAt - The client's `vouchingExpiresAt`, or null when an
 *   administrator created it rather than an anchor.
 * @param now - The instant to judge against.
 * @returns Whether the client is vouched, whether that vouching has lapsed, and how
 *   long is left. The instant of expiry counts as lapsed.
 * @example
 * ```ts
 * if (describeVouching(client.vouchingExpiresAt, context.clock()).expired) {
 *   return { ok: false, reason: "vouching-expired" };
 * }
 * ```
 */
export function describeVouching(
  expiresAt: Date | null | undefined,
  now: Date,
): VouchingState {
  if (expiresAt === null || expiresAt === undefined) {
    return {
      vouched: false,
      expired: false,
      secondsRemaining: 0,
      daysRemaining: 0,
    };
  }

  const remaining = Math.floor((expiresAt.getTime() - now.getTime()) / 1000);
  if (remaining <= 0) {
    return {
      vouched: true,
      expired: true,
      secondsRemaining: 0,
      daysRemaining: 0,
    };
  }

  return {
    vouched: true,
    expired: false,
    secondsRemaining: remaining,
    daysRemaining: Math.floor(remaining / SECONDS_PER_DAY),
  };
}
