/**
 * Dynamic client registration, vouched by the endpoint's trust anchor.
 *
 * Signet refuses open registration everywhere, and this route does not change
 * that. What it changes is the *narrowness* of the refusal: an endpoint that names
 * a trust anchor accepts registrations carrying a software statement that anchor
 * signed, and every other endpoint - which is every endpoint by default - answers
 * 404 here and advertises nothing. Capability arrives by adding a rule, never by
 * removing a restriction.
 *
 * ## The order the checks run in, and why it is that order
 *
 * 1. **The rule, before anything else.** An endpoint with no anchor must be
 *    indistinguishable from one where this route does not exist, so nothing is
 *    parsed, fetched or audited before the rule has been found.
 * 2. **The body shape.** Exactly `software_statement`, and nothing beside it. A
 *    request carrying its own `redirect_uris` is refused rather than having them
 *    ignored - ignoring is safe today and a merge waiting to be written tomorrow,
 *    and a merged redirect URI is a client the anchor never vouched for.
 * 3. **The signature**, against keys fetched through the outbound guard. The
 *    address is administrator-supplied, so this is exactly the untrusted-URL case
 *    the guard exists for, and a fetch that fails refuses the registration rather
 *    than falling back to anything.
 * 4. **The claims**: the anchor named by the rule, within validity, within the
 *    endpoint's vouching ceiling.
 * 5. **The metadata**, against the same rules any other client is registered
 *    under. The anchor vouches for the metadata's origin, not for its validity.
 * 6. **The insert**, which is also the replay check. `(endpoint_id,
 *    vouched_statement_id)` is unique, so two registrations racing on one
 *    statement are arbitrated by the database: exactly one wins.
 *
 * Every outcome is audited, and the audit detail carries the anchor and the
 * statement's identifier and never the statement or the secret. A statement is a
 * bearer credential for one registration, and a secret is a bearer credential for
 * everything the client can do.
 *
 * Author: John Grimes
 */

import {
  extractVouchedClientMetadata,
  parseRegistrationBody,
  PERMITTED_STATEMENT_ALGORITHMS,
  validateSoftwareStatement,
} from "@signet/core";
import {
  createVouchedClient,
  endpointAllowsClientType,
  getEndpointTrustAnchor,
  hashPassword,
  isUniqueViolation,
  withTenantScope,
} from "@signet/db";

import { verifyTrustedJws } from "./trustedJws.js";
import {
  generateClientId,
  generateClientSecret,
} from "../admin/credentials.js";
import { requestMetadata } from "../http/requestMeta.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { VouchedClientMetadata, VouchedStatement } from "@signet/core";
import type { Client } from "@signet/db";
import type { Context } from "hono";

/**
 * The refusals RFC 7591 §3.2.2 defines, as this endpoint uses them.
 *
 * Three, and each says whose mistake it was: the caller built the request wrongly,
 * the anchor's statement is not one this endpoint honours, or the statement was
 * fine and describes a client Signet will not operate. An app developer reading a
 * log can act on all three differently.
 */
type RegistrationErrorCode =
  "invalid_request" | "invalid_software_statement" | "invalid_client_metadata";

/** What the registration response says about a new client. */
function registrationView(
  client: Client,
  secret: string | undefined,
): Record<string, unknown> {
  return {
    client_id: client.clientId,
    client_id_issued_at: Math.floor(client.createdAt.getTime() / 1000),
    ...(secret === undefined
      ? {}
      : {
          client_secret: secret,
          // Zero means "does not expire", per RFC 7591 §3.2.1. The vouching does
          // expire, and that is a different thing: the secret stays valid, and the
          // client stops being able to obtain tokens with it.
          client_secret_expires_at: 0,
        }),
    client_name: client.name,
    redirect_uris: client.redirectUris,
    grant_types: client.grantTypes,
    token_endpoint_auth_method: authMethodFor(client),
    scope: client.allowedScopes.join(" "),
    ...(client.logoUrl === null ? {} : { logo_uri: client.logoUrl }),
    ...(client.jwksUri === null ? {} : { jwks_uri: client.jwksUri }),
    ...(client.jwks === null ? {} : { jwks: client.jwks }),
  };
}

/**
 * The authentication method a registered client presents.
 *
 * Derived from the stored client type rather than echoed from the statement, so
 * the response describes the registration as it exists rather than as it was
 * asked for. `client_secret_basic` is the symmetric answer because it is the one
 * an RFC 7591 client assumes; `client_secret_post` is accepted at the token
 * endpoint too.
 */
function authMethodFor(client: Client): string {
  switch (client.clientType) {
    case "public": {
      return "none";
    }
    case "confidential-symmetric": {
      return "client_secret_basic";
    }
    default: {
      return "private_key_jwt";
    }
  }
}

/** The client input a statement's metadata describes. */
function clientInputFrom(
  metadata: VouchedClientMetadata,
  secretHash: string | null,
) {
  return {
    clientId: generateClientId(metadata.name),
    name: metadata.name,
    clientType: metadata.clientType,
    redirectUris: [...metadata.redirectUris],
    grantTypes: [...metadata.grantTypes],
    allowedScopes: [...metadata.scopes],
    // Active immediately. The anchor's signature is the approval, which is the
    // whole difference between this and the developer portal's queue.
    status: "active" as const,
    secretHash,
    logoUrl: metadata.logoUri ?? null,
    contactEmail: metadata.contactEmail ?? null,
    jwks: metadata.jwks ?? null,
    jwksUri: metadata.jwksUri ?? null,
  };
}

/**
 * Handles `POST {iss}/register`: registers a client an anchor vouched for.
 *
 * @param context - The server's dependencies.
 * @returns The Hono handler.
 * @example
 * ```ts
 * router.post(path("/register"), rateLimit("register", ...), registerHandler(context));
 * ```
 */
export function registerHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const issuerContext = c.get("issuer");
    const { endpoint, tenant } = issuerContext;
    const metadata = requestMetadata(c);

    /** Records the outcome and produces the response. */
    const audited = async (
      detail: Record<string, unknown>,
      body: Record<string, unknown>,
      status: 201 | 400,
    ) => {
      await context.audit.record(context.db, {
        tenantId: tenant.id,
        endpointId: endpoint.id,
        endpointSlug: endpoint.slug,
        // No identity to attribute this to: whoever holds a statement the anchor
        // signed is entitled to register with it, and they have no account here.
        actor: { type: "system" },
        action: "client.registration-attempted",
        target: { type: "client" },
        detail,
        ...metadata,
      });
      c.header("Cache-Control", "no-store");
      return c.json(body, status);
    };

    /** Refuses, with the reason in the audit trail and in the response. */
    const refuse = async (
      anchorIssuer: string,
      code: RegistrationErrorCode,
      description: string,
      statementId?: string,
    ) =>
      await audited(
        {
          outcome: "refused",
          anchorIssuer,
          error: code,
          description,
          ...(statementId === undefined ? {} : { statementId }),
        },
        { error: code, error_description: description },
        400,
      );

    const anchor = await withTenantScope(
      context.db,
      issuerContext.scope,
      (bound) => getEndpointTrustAnchor(bound),
    );
    if (anchor === undefined) {
      // Indistinguishable from a route that does not exist, which is what an
      // endpoint with no anchor must look like. Not audited: there is nothing to
      // attribute it to, and an unrouted path is not an event.
      return c.json(
        {
          error: "not_found",
          error_description:
            "This endpoint does not accept dynamic client registration",
        },
        404,
      );
    }

    // A body that is not JSON at all reads as `null`, which the parser refuses
    // as "not an object" - the same answer it gives for a JSON scalar, and the
    // right one for both.
    const raw: unknown = await c.req.json().catch(() => null);
    const parsed = parseRegistrationBody(raw);
    if (!parsed.ok) {
      return await refuse(anchor.issuer, "invalid_request", parsed.description);
    }

    const verified = await verifyTrustedJws(context, {
      jwksUri: anchor.jwksUri,
      token: parsed.softwareStatement,
      algorithms: PERMITTED_STATEMENT_ALGORITHMS,
      noun: "software statement",
    });
    if (!verified.ok) {
      return await refuse(
        anchor.issuer,
        "invalid_software_statement",
        verified.description,
      );
    }

    const validated = validateSoftwareStatement({
      claims: verified.claims,
      anchorIssuer: anchor.issuer,
      maxVouchingDays: anchor.maxVouchingDays,
      now: context.clock(),
    });
    if (!validated.ok) {
      return await refuse(
        anchor.issuer,
        "invalid_software_statement",
        validated.description,
      );
    }
    const statement: VouchedStatement = validated.statement;

    const described = extractVouchedClientMetadata(verified.claims);
    if (!described.ok) {
      return await refuse(
        anchor.issuer,
        "invalid_client_metadata",
        described.description,
        statement.statementId,
      );
    }

    // The endpoint's own admission rules, which the anchor knows nothing about.
    // Refusing here rather than registering produces a client that works, instead
    // of one that appears configured and fails every authorization it attempts.
    if (!endpointAllowsClientType(endpoint, described.metadata.clientType)) {
      return await refuse(
        anchor.issuer,
        "invalid_client_metadata",
        `This endpoint does not admit ${described.metadata.clientType} clients`,
        statement.statementId,
      );
    }

    const secret =
      described.metadata.clientType === "confidential-symmetric"
        ? generateClientSecret()
        : undefined;
    const input = clientInputFrom(
      described.metadata,
      secret === undefined ? null : await hashPassword(secret),
    );

    let client: Client;
    try {
      client = await withTenantScope(context.db, issuerContext.scope, (bound) =>
        createVouchedClient(bound, input, {
          vouchedByIssuer: statement.issuer,
          vouchedStatementId: statement.statementId,
          vouchingExpiresAt: statement.expiresAt,
        }),
      );
    } catch (error) {
      if (!isUniqueViolation(error)) {
        throw error;
      }
      // The unique constraint is the replay check, and it is also what arbitrates
      // a race: the losing insert lands here whichever order the two interleaved
      // in. A read-then-insert would let both find nothing.
      return await refuse(
        anchor.issuer,
        "invalid_software_statement",
        "That software statement has already been used to register a client here",
        statement.statementId,
      );
    }

    return await audited(
      {
        outcome: "registered",
        anchorIssuer: anchor.issuer,
        statementId: statement.statementId,
        clientId: client.clientId,
        vouchingExpiresAt: statement.expiresAt.toISOString(),
      },
      registrationView(client, secret),
      201,
    );
  };
}
