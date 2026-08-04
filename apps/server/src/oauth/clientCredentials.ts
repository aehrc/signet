/**
 * Extraction of the client's credential from a token endpoint request.
 *
 * Pure: this decides *which* authentication method the request is using and
 * pulls the material out of it, but verifies nothing. Verification needs the
 * client row, a password hash comparison and a JWKS, and lives in
 * `./clientAuthentication.ts`.
 *
 * Separating the two matters because most of the ways this can go wrong are
 * syntactic, and syntax is where the interoperability problems are: a client
 * that sends its secret both in the header and in the body, a `Basic` value
 * that is not base64, a `client_id` in the header that disagrees with the one in
 * the body. Each of those has a specific correct response, and none of them
 * should require a database round trip to produce.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
 * @see https://datatracker.ietf.org/doc/html/rfc7523#section-2.2
 * @see https://hl7.org/fhir/smart-app-launch/backend-services.html
 *
 * Author: John Grimes
 */

/** The `client_assertion_type` RFC 7523 defines for a JWT bearer assertion. */
export const JWT_BEARER_ASSERTION_TYPE =
  "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/** The authentication methods Signet accepts at the token endpoint. */
export type ClientAuthMethod =
  | "client_secret_basic"
  | "client_secret_post"
  | "private_key_jwt"
  /** A public client, which authenticates with PKCE rather than a credential. */
  | "none";

/** A credential extracted from a request, not yet verified. */
export type PresentedCredential =
  | {
      readonly method: "client_secret_basic" | "client_secret_post";
      readonly clientId: string;
      readonly clientSecret: string;
    }
  | {
      readonly method: "private_key_jwt";
      /**
       * Present only when the request also sent `client_id`.
       *
       * RFC 7523 makes it optional, because the assertion's `sub` names the
       * client. When both are present they must agree, which is checked here.
       */
      readonly clientId: string | undefined;
      readonly assertion: string;
    }
  | { readonly method: "none"; readonly clientId: string };

/** Why a credential could not be extracted. */
export type CredentialRefusal =
  /** No `client_id` anywhere, and no assertion to carry one. */
  | { readonly code: "invalid_request"; readonly description: string }
  /** Present but unusable: a malformed `Basic` header, or contradictory ids. */
  | { readonly code: "invalid_client"; readonly description: string };

/** The outcome of extracting a credential. */
export type CredentialExtraction =
  | { readonly ok: true; readonly credential: PresentedCredential }
  | { readonly ok: false; readonly refusal: CredentialRefusal };

/** The token endpoint form fields this module reads. */
export interface CredentialFields {
  readonly clientId?: string;
  readonly clientSecret?: string;
  readonly clientAssertion?: string;
  readonly clientAssertionType?: string;
}

/** A decoded `Basic` credential. */
interface BasicCredential {
  readonly clientId: string;
  readonly clientSecret: string;
}

/**
 * Reverses `application/x-www-form-urlencoded` encoding.
 *
 * RFC 6749 §2.3.1 requires both halves of a `Basic` credential to be
 * form-urlencoded before base64, which matters for any secret containing a
 * colon: without decoding, the colon inside the secret would be indistinguishable
 * from the separator. Returns undefined on an invalid escape rather than
 * throwing, so a hostile header cannot produce a 500.
 */
function formUrlDecode(value: string): string | undefined {
  try {
    return decodeURIComponent(value.replaceAll("+", " "));
  } catch {
    return undefined;
  }
}

/**
 * Standard base64, with optional padding.
 *
 * Checked explicitly because Node's base64 decoder is lenient: it silently skips
 * characters outside the alphabet, so `Buffer.from("!!!!", "base64")` succeeds
 * and yields nothing. Without this, a header of pure garbage would decode to an
 * empty string and be reported as a malformed *credential* rather than as a
 * malformed header - the same response, but for the wrong reason, and one that
 * stops being the same response the moment the code below changes.
 */
const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * Decodes an `Authorization: Basic` header.
 *
 * @returns The credential, or undefined when the header is not a well-formed
 *   `Basic` value. An absent header is the caller's business, not this
 *   function's.
 */
function decodeBasic(header: string): BasicCredential | undefined {
  const encoded = header.slice("Basic ".length).trim();
  if (!BASE64_PATTERN.test(encoded)) {
    return undefined;
  }

  const decoded = Buffer.from(encoded, "base64").toString("utf8");
  const separator = decoded.indexOf(":");
  if (separator === -1) {
    return undefined;
  }

  const clientId = formUrlDecode(decoded.slice(0, separator));
  const clientSecret = formUrlDecode(decoded.slice(separator + 1));
  if (clientId === undefined || clientSecret === undefined) {
    return undefined;
  }
  if (clientId.length === 0) {
    return undefined;
  }

  return { clientId, clientSecret };
}

/** Treats a blank string as absent, which is how form encoding conveys it. */
function present(value: string | undefined): string | undefined {
  return value === undefined || value.length === 0 ? undefined : value;
}

/**
 * Extracts the client credential from a token endpoint request.
 *
 * @param authorization - The raw `Authorization` header, if any.
 * @param fields - The parsed form body fields.
 */
export function extractClientCredential(
  authorization: string | undefined,
  fields: CredentialFields,
): CredentialExtraction {
  const bodyClientId = present(fields.clientId);
  const bodySecret = present(fields.clientSecret);
  const assertion = present(fields.clientAssertion);
  const assertionType = present(fields.clientAssertionType);
  // The scheme name is case-insensitive per RFC 7235 §2.1.
  const basicHeader =
    authorization !== undefined &&
    authorization.slice(0, 6).toLowerCase() === "basic "
      ? authorization
      : undefined;

  // Presenting more than one credential is refused rather than resolved by
  // precedence. RFC 6749 §2.3 forbids it, and a request carrying two is either a
  // misconfigured client or an attempt to have the server pick the weaker one.
  const methods = [
    basicHeader !== undefined,
    bodySecret !== undefined,
    assertion !== undefined,
  ];
  if (methods.filter(Boolean).length > 1) {
    return {
      ok: false,
      refusal: {
        code: "invalid_request",
        description:
          "The request presents more than one client authentication method",
      },
    };
  }

  if (basicHeader !== undefined) {
    const basic = decodeBasic(basicHeader);
    if (basic === undefined) {
      return {
        ok: false,
        refusal: {
          code: "invalid_client",
          description:
            "The Authorization header is not a valid Basic credential",
        },
      };
    }
    if (bodyClientId !== undefined && bodyClientId !== basic.clientId) {
      return {
        ok: false,
        refusal: {
          code: "invalid_client",
          description:
            "client_id in the request body does not match the Authorization header",
        },
      };
    }
    return {
      ok: true,
      credential: { method: "client_secret_basic", ...basic },
    };
  }

  if (assertion !== undefined) {
    if (assertionType !== JWT_BEARER_ASSERTION_TYPE) {
      return {
        ok: false,
        refusal: {
          code: "invalid_request",
          description: `client_assertion_type must be ${JWT_BEARER_ASSERTION_TYPE}`,
        },
      };
    }
    return {
      ok: true,
      credential: {
        method: "private_key_jwt",
        clientId: bodyClientId,
        assertion,
      },
    };
  }

  if (assertionType !== undefined) {
    return {
      ok: false,
      refusal: {
        code: "invalid_request",
        description: "client_assertion_type was sent without client_assertion",
      },
    };
  }

  if (bodyClientId === undefined) {
    return {
      ok: false,
      refusal: {
        code: "invalid_request",
        description: "client_id is required",
      },
    };
  }

  return bodySecret === undefined
    ? { ok: true, credential: { method: "none", clientId: bodyClientId } }
    : {
        ok: true,
        credential: {
          method: "client_secret_post",
          clientId: bodyClientId,
          clientSecret: bodySecret,
        },
      };
}

/**
 * The `client_id` a credential names, before any verification.
 *
 * For `private_key_jwt` the request need not carry one, in which case the
 * assertion's `sub` supplies it - so this can legitimately be undefined.
 */
export function credentialClientId(
  credential: PresentedCredential,
): string | undefined {
  return credential.clientId;
}

/**
 * Whether a client's registered posture permits the method it used.
 *
 * The mapping is one-to-one and there is no latitude in it. A public client that
 * presents a secret is not "a confidential client today": either the
 * registration is wrong or somebody has guessed a secret that does not exist.
 */
export function methodMatchesClientType(
  method: ClientAuthMethod,
  clientType: "public" | "confidential-symmetric" | "confidential-asymmetric",
): boolean {
  switch (clientType) {
    case "public": {
      return method === "none";
    }
    case "confidential-symmetric": {
      return (
        method === "client_secret_basic" || method === "client_secret_post"
      );
    }
    case "confidential-asymmetric": {
      return method === "private_key_jwt";
    }
  }
}
