/**
 * Verifying the client at the token endpoint.
 *
 * The syntactic work is done in `./clientCredentials.ts` and the assertion's claim
 * checks in `./clientAssertion.ts`; this module is where those meet the database
 * and the client's keys. Its ordering is the security-bearing part:
 *
 * 1. Extract the credential, and refuse a request that presents more than one.
 * 2. Resolve the `client_id` **within this endpoint**. A client registered on
 *    another endpoint reads as unknown, not as a client that fails a later check.
 * 3. Refuse a method that does not match the client's registered posture. A public
 *    client presenting a secret is not a confidential client for one request.
 * 4. Verify the credential.
 * 5. For `private_key_jwt` only: book the assertion's `jti`, **after** the
 *    signature has verified. Booking first would let anybody with the client's id
 *    fill the replay ledger with `jti` values the client had not used, and then
 *    the client's own assertions would be rejected as replays.
 *
 * Every refusal is `invalid_client` with a description that names the class of
 * problem and never the credential. The uniform code is deliberate: telling a
 * caller apart "no such client" from "wrong secret" is a client-enumeration
 * oracle.
 */

import {
  isClientUsable,
  recordClientJwksFetch,
  recordJti,
  resolveClientScope,
  verifyPassword,
} from "@signet/db";
import {
  createLocalJWKSet,
  decodeJwt,
  decodeProtectedHeader,
  jwtVerify,
} from "jose";

import {
  PERMITTED_ASSERTION_ALGORITHMS,
  validateClientAssertion,
} from "./clientAssertion.js";
import {
  extractClientCredential,
  methodMatchesClientType,
} from "./clientCredentials.js";
import { asKeySet } from "../keys/keySet.js";
import { fetchGuardedJson } from "../security/outboundFetch.js";

import type { ServerContext, ResolvedIssuerContext } from "../context.js";
import type {
  ClientAuthMethod,
  CredentialFields,
} from "./clientCredentials.js";
import type { FormBody } from "./grants/types.js";
import type { TokenErrorCode } from "../http/oauthErrors.js";
import type { Client, ClientScope } from "@signet/db";
import type { JSONWebKeySet } from "jose";

/** An authenticated client, with the scope its subsequent queries need. */
export interface AuthenticatedClient {
  readonly scope: ClientScope;
  readonly client: Client;
  readonly method: ClientAuthMethod;
}

/** The outcome of authenticating a client. */
export type ClientAuthResult =
  | { readonly ok: true; readonly authenticated: AuthenticatedClient }
  | {
      readonly ok: false;
      readonly code: TokenErrorCode;
      readonly description: string;
      /** The `client_id` that was claimed, for the audit event. */
      readonly clientId?: string;
      /**
       * Set when the refusal was a replayed client assertion.
       *
       * Worth its own audit action: it is the only refusal here that is evidence
       * of an attack rather than of a misconfiguration.
       */
      readonly assertionReplayed?: boolean;
    };

/** Builds a refusal. */
function refuse(
  code: TokenErrorCode,
  description: string,
  clientId?: string,
): ClientAuthResult {
  return {
    ok: false,
    code,
    description,
    ...(clientId === undefined ? {} : { clientId }),
  };
}

/**
 * Reads the `client_id` a `private_key_jwt` request is about, without verifying.
 *
 * The client has to be resolved before its keys can be found, so the assertion's
 * `sub` must be read before the signature can be checked. Nothing is trusted as a
 * result: the claim is used only to look a row up, and `validateClientAssertion`
 * re-checks `sub` against the resolved client afterwards.
 */
function unverifiedAssertionSubject(assertion: string): string | undefined {
  try {
    const claims = decodeJwt(assertion);
    return typeof claims.sub === "string" && claims.sub.length > 0
      ? claims.sub
      : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Loads the key set a client's assertions are verified against.
 *
 * An inline `jwks` is used as-is. A `jwks_uri` is fetched through the SSRF guard
 * on every authentication rather than cached: a cached JWKS that outlived the
 * client's own key rotation would let a withdrawn key keep authenticating, and
 * that is a worse trade than one extra outbound request per backend-services
 * token. The `jwks_cached_at` column records the fetch so an operator can see the
 * rate, not so a later request can skip it.
 */
async function loadClientKeySet(
  context: ServerContext,
  scope: ClientScope,
  client: Client,
): Promise<
  | { readonly ok: true; readonly keys: JSONWebKeySet }
  | { readonly ok: false; readonly description: string }
> {
  if (client.jwks !== null) {
    const keys = asKeySet(client.jwks);
    return keys === undefined
      ? {
          ok: false,
          description: "This client's registered jwks has no keys array",
        }
      : { ok: true, keys };
  }
  if (client.jwksUri === null) {
    return {
      ok: false,
      description:
        "This client is registered for private_key_jwt but has neither jwks nor jwks_uri",
    };
  }

  const fetched = await fetchGuardedJson(client.jwksUri, {
    allowPrivateAddresses: context.config.allowPrivateOutboundFetches,
  });
  if (!fetched.ok) {
    return {
      ok: false,
      description: `The client's jwks_uri could not be used: ${fetched.description}`,
    };
  }

  const keys = asKeySet(fetched.value);
  if (keys === undefined) {
    return {
      ok: false,
      description: "The client's jwks_uri did not return a JWK Set",
    };
  }

  await recordClientJwksFetch(context.db, scope, context.clock());
  return { ok: true, keys };
}

/**
 * Verifies a `private_key_jwt` assertion and books its `jti`.
 *
 * @param context - The server's dependencies.
 * @param issuerContext - The endpoint the assertion must be addressed to.
 * @param scope - The resolved client.
 * @param client - The client's registration.
 * @param assertion - The compact JWT the request presented.
 * @param presentedClientId - The `client_id` the request also carried, if any.
 */
async function verifyAssertion(
  context: ServerContext,
  issuerContext: ResolvedIssuerContext,
  scope: ClientScope,
  client: Client,
  assertion: string,
  presentedClientId: string | undefined,
): Promise<ClientAuthResult> {
  let algorithm: string | undefined;
  let claims: Record<string, unknown>;
  try {
    algorithm = decodeProtectedHeader(assertion).alg;
    claims = decodeJwt(assertion);
  } catch {
    return refuse(
      "invalid_client",
      "client_assertion is not a well-formed JWT",
      client.clientId,
    );
  }

  const validation = validateClientAssertion({
    claims,
    algorithm,
    // Both the token endpoint and the issuer are accepted; see
    // `validateClientAssertion` for why.
    acceptedAudiences: [issuerContext.urls.token, issuerContext.issuer],
    presentedClientId: presentedClientId ?? client.clientId,
    nowSeconds: Math.floor(context.clock().getTime() / 1000),
  });
  if (!validation.ok) {
    return refuse("invalid_client", validation.description, client.clientId);
  }
  if (validation.assertion.clientId !== client.clientId) {
    return refuse(
      "invalid_client",
      "The client assertion's sub does not name this client",
      client.clientId,
    );
  }

  const keySet = await loadClientKeySet(context, scope, client);
  if (!keySet.ok) {
    return refuse("invalid_client", keySet.description, client.clientId);
  }

  try {
    await jwtVerify(assertion, createLocalJWKSet(keySet.keys), {
      algorithms: [...PERMITTED_ASSERTION_ALGORITHMS],
    });
  } catch {
    return refuse(
      "invalid_client",
      "The client assertion's signature could not be verified",
      client.clientId,
    );
  }

  // Only now, with a verified signature, is the `jti` booked. See the module
  // header for why the order matters.
  const booked = await recordJti(
    context.db,
    scope,
    validation.assertion.jti,
    validation.assertion.expiresAt,
  );
  if (booked.status === "already-seen") {
    return {
      ok: false,
      code: "invalid_client",
      description: "This client assertion has already been presented",
      clientId: client.clientId,
      assertionReplayed: true,
    };
  }

  return {
    ok: true,
    authenticated: { scope, client, method: "private_key_jwt" },
  };
}

/**
 * Verifies a symmetric client secret.
 *
 * An expired secret is refused even when it matches: rotation is only meaningful
 * if the outgoing secret actually stops working.
 */
async function verifySecret(
  context: ServerContext,
  scope: ClientScope,
  client: Client,
  method: "client_secret_basic" | "client_secret_post",
  presented: string,
): Promise<ClientAuthResult> {
  if (client.secretHash === null) {
    return refuse(
      "invalid_client",
      "This client has no secret configured",
      client.clientId,
    );
  }
  if (
    client.secretExpiresAt !== null &&
    client.secretExpiresAt.getTime() <= context.clock().getTime()
  ) {
    return refuse(
      "invalid_client",
      "This client's secret has expired and must be rotated",
      client.clientId,
    );
  }
  if (!(await verifyPassword(presented, client.secretHash))) {
    return refuse(
      "invalid_client",
      "Client authentication failed",
      client.clientId,
    );
  }
  return { ok: true, authenticated: { scope, client, method } };
}

/**
 * Collects the credential fields out of a parsed form body.
 *
 * All three authenticated endpoints — token, introspection and revocation — read
 * the same four fields, and each has to omit rather than nullify an absent one to
 * satisfy `exactOptionalPropertyTypes`. Doing that in one place keeps the three
 * handlers from drifting into accepting slightly different sets.
 */
export function credentialFieldsFrom(body: FormBody): CredentialFields {
  /** Reads a single-valued field, treating a repeat or a file as absent. */
  const field = (name: string): string | undefined => {
    const value = body[name];
    return typeof value === "string" && value.length > 0 ? value : undefined;
  };

  const clientId = field("client_id");
  const clientSecret = field("client_secret");
  const clientAssertion = field("client_assertion");
  const clientAssertionType = field("client_assertion_type");

  return {
    ...(clientId === undefined ? {} : { clientId }),
    ...(clientSecret === undefined ? {} : { clientSecret }),
    ...(clientAssertion === undefined ? {} : { clientAssertion }),
    ...(clientAssertionType === undefined ? {} : { clientAssertionType }),
  };
}

/**
 * Authenticates the client behind a token endpoint request.
 *
 * @param context - The server's dependencies.
 * @param issuerContext - The endpoint the request arrived on.
 * @param authorization - The raw `Authorization` header, if any.
 * @param fields - The parsed form body.
 */
export async function authenticateClient(
  context: ServerContext,
  issuerContext: ResolvedIssuerContext,
  authorization: string | undefined,
  fields: CredentialFields,
): Promise<ClientAuthResult> {
  const extraction = extractClientCredential(authorization, fields);
  if (!extraction.ok) {
    return refuse(
      extraction.refusal.code,
      extraction.refusal.description,
      fields.clientId,
    );
  }
  const credential = extraction.credential;

  const clientId =
    credential.clientId ??
    (credential.method === "private_key_jwt"
      ? unverifiedAssertionSubject(credential.assertion)
      : undefined);
  if (clientId === undefined) {
    return refuse(
      "invalid_request",
      "client_id is required, or the assertion must carry a sub claim",
    );
  }

  const resolved = await resolveClientScope(
    context.db,
    issuerContext.scope,
    clientId,
  );
  if (resolved === undefined) {
    return refuse("invalid_client", "Client authentication failed", clientId);
  }
  const { scope, client } = resolved;

  if (!isClientUsable(client)) {
    return refuse(
      "invalid_client",
      `This client's registration is ${client.status}`,
      clientId,
    );
  }

  if (!methodMatchesClientType(credential.method, client.clientType)) {
    return refuse(
      "invalid_client",
      `A ${client.clientType} client must authenticate with a different method`,
      clientId,
    );
  }

  switch (credential.method) {
    case "none": {
      // A public client is authenticated by the PKCE verifier it presents with
      // the code, which the grant handler checks. There is nothing to verify here.
      return { ok: true, authenticated: { scope, client, method: "none" } };
    }
    case "client_secret_basic":
    case "client_secret_post": {
      return await verifySecret(
        context,
        scope,
        client,
        credential.method,
        credential.clientSecret,
      );
    }
    case "private_key_jwt": {
      return await verifyAssertion(
        context,
        issuerContext,
        scope,
        client,
        credential.assertion,
        credential.clientId,
      );
    }
  }
}
