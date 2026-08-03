/**
 * Validation of an upstream identity provider's discovery document.
 *
 * Pure: fetching the document is the server's job, and it goes through the SSRF
 * guard because the URL comes from an operator. What is decided here is whether
 * the document that came back may be used to send a person's browser somewhere
 * and to redeem a code — which is a security decision, not a parsing one.
 *
 * Three rules carry the weight.
 *
 * The `issuer` in the document must equal the issuer that was asked about. OpenID
 * Connect Discovery §4.3 requires this, and it is what closes the substitution
 * attack: without it, a provider that has been given the wrong discovery URL - or
 * that redirects to one - can name any endpoints it likes and receive
 * authorization codes minted in another provider's name.
 *
 * Every endpoint must be HTTPS. A discovery document is fetched over TLS, but
 * nothing stops it naming an `http://` authorization endpoint, which would put
 * the person's browser - carrying the state parameter - onto a plaintext hop.
 *
 * Nothing here is optional-but-tolerated. A document missing the token endpoint
 * or the JWKS URI is unusable, so it is refused at configuration time rather than
 * producing an obscure failure the first time somebody tries to sign in.
 *
 * @see https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
 */

/** The parts of a discovery document Signet uses. */
export interface UpstreamMetadata {
  readonly issuer: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly jwksUri: string;
  /** Absent on a provider that publishes no userinfo endpoint. */
  readonly userinfoEndpoint?: string;
  /** Absent when the provider does not advertise them. */
  readonly codeChallengeMethods?: readonly string[];
  readonly idTokenSigningAlgorithms?: readonly string[];
}

/** Why a discovery document was refused. */
export type MetadataRefusalCode =
  | "not-an-object"
  | "missing-issuer"
  | "issuer-mismatch"
  | "missing-endpoint"
  | "insecure-endpoint"
  | "malformed-endpoint";

/** The outcome of validating a discovery document. */
export type MetadataValidation =
  | { readonly ok: true; readonly metadata: UpstreamMetadata }
  | {
      readonly ok: false;
      readonly code: MetadataRefusalCode;
      readonly description: string;
    };

/** Reads a string property, or undefined when it is absent or not a string. */
function stringField(
  document: Record<string, unknown>,
  name: string,
): string | undefined {
  const value = document[name];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

/** Reads an array-of-strings property, dropping entries that are not strings. */
function stringArrayField(
  document: Record<string, unknown>,
  name: string,
): readonly string[] | undefined {
  const value = document[name];
  if (!Array.isArray(value)) {
    return undefined;
  }
  return value.filter((entry): entry is string => typeof entry === "string");
}

/** A refusal, built where the reason is known. */
function refuse(
  code: MetadataRefusalCode,
  description: string,
): MetadataValidation {
  return { ok: false, code, description };
}

/**
 * Checks that a URL is absolute and HTTPS.
 *
 * Returns the refusal rather than a boolean, so the caller can say which field
 * was wrong and how - an operator debugging a federation setup needs the name of
 * the offending field, not "invalid metadata".
 */
function checkEndpoint(
  name: string,
  value: string,
): MetadataValidation | undefined {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return refuse(
      "malformed-endpoint",
      `The provider's ${name} is not an absolute URL`,
    );
  }
  if (url.protocol !== "https:") {
    return refuse(
      "insecure-endpoint",
      `The provider's ${name} is not HTTPS, so it will not be used`,
    );
  }
  return undefined;
}

/**
 * Validates a fetched discovery document against the issuer it should describe.
 *
 * @param document - The parsed JSON, as fetched. Untrusted.
 * @param expectedIssuer - The issuer the operator configured.
 * @param options - Overrides for a development deployment.
 * @param options.allowInsecureEndpoints - Permits `http://` endpoints. Intended
 *   for a local provider in a docker-compose stack, and gated on the same
 *   configuration flag that relaxes the outbound-fetch guard.
 * @returns The parts Signet uses, or why the document was refused.
 */
export function validateUpstreamMetadata(
  document: unknown,
  expectedIssuer: string,
  options: { readonly allowInsecureEndpoints?: boolean } = {},
): MetadataValidation {
  if (typeof document !== "object" || document === null) {
    return refuse(
      "not-an-object",
      "The discovery document is not a JSON object",
    );
  }
  const record = document as Record<string, unknown>;

  const issuer = stringField(record, "issuer");
  if (issuer === undefined) {
    return refuse("missing-issuer", "The discovery document has no issuer");
  }
  // Compared exactly, as Discovery §4.3 requires. A trailing slash is a different
  // issuer as far as every token this provider mints is concerned, so tolerating
  // one here would only move the mismatch to `iss` validation later.
  if (issuer !== expectedIssuer) {
    return refuse(
      "issuer-mismatch",
      `The discovery document is issued by ${issuer}, not ${expectedIssuer}`,
    );
  }

  const authorizationEndpoint = stringField(record, "authorization_endpoint");
  const tokenEndpoint = stringField(record, "token_endpoint");
  const jwksUri = stringField(record, "jwks_uri");
  const userinfoEndpoint = stringField(record, "userinfo_endpoint");

  // Presence first, one field at a time, so the refusal names the field that is
  // missing. Checked before the scheme, because "no token_endpoint" and "an
  // http:// token_endpoint" are different conversations with the provider's
  // administrator.
  if (authorizationEndpoint === undefined) {
    return refuse(
      "missing-endpoint",
      "The provider published no authorization_endpoint",
    );
  }
  if (tokenEndpoint === undefined) {
    return refuse(
      "missing-endpoint",
      "The provider published no token_endpoint",
    );
  }
  if (jwksUri === undefined) {
    return refuse("missing-endpoint", "The provider published no jwks_uri");
  }

  if (options.allowInsecureEndpoints !== true) {
    for (const [name, value] of [
      ["authorization_endpoint", authorizationEndpoint],
      ["token_endpoint", tokenEndpoint],
      ["jwks_uri", jwksUri],
    ] as const) {
      const problem = checkEndpoint(name, value);
      if (problem !== undefined) {
        return problem;
      }
    }
  }

  const codeChallengeMethods = stringArrayField(
    record,
    "code_challenge_methods_supported",
  );
  const idTokenSigningAlgorithms = stringArrayField(
    record,
    "id_token_signing_alg_values_supported",
  );

  return {
    ok: true,
    metadata: {
      issuer,
      authorizationEndpoint,
      tokenEndpoint,
      jwksUri,
      ...(userinfoEndpoint === undefined ? {} : { userinfoEndpoint }),
      ...(codeChallengeMethods === undefined ? {} : { codeChallengeMethods }),
      ...(idTokenSigningAlgorithms === undefined
        ? {}
        : { idTokenSigningAlgorithms }),
    },
  };
}

/**
 * Whether the provider will accept PKCE with S256.
 *
 * Signet always sends a challenge. What this decides is whether the provider said
 * it understands one: a provider that advertises the methods it supports and does
 * not list `S256` will ignore the challenge, and an operator should be told that
 * the protection they think they have is not there.
 *
 * A provider that advertises nothing is given the benefit of the doubt, because
 * `code_challenge_methods_supported` is optional and plenty of providers support
 * PKCE without publishing it.
 *
 * @param metadata - The validated discovery document.
 */
export function supportsPkce(metadata: UpstreamMetadata): boolean {
  return (
    metadata.codeChallengeMethods === undefined ||
    metadata.codeChallengeMethods.includes("S256")
  );
}
