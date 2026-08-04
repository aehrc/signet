/**
 * Reading the `jti` out of a presented access token.
 *
 * Introspection and revocation both take an arbitrary string from a request body
 * and have to find the row it names. The signature is deliberately *not* verified
 * on the way: a token signed by a key that has since been retired is still a token
 * Signet issued, and refusing to introspect or revoke it would leave a resource
 * server unable to act on something it legitimately holds. The `jti` appearing in
 * this endpoint's own `access_tokens` table is the authority, not the signature.
 *
 * Hand-decoded rather than delegated to `jose`, because `decodeJwt` throws for a
 * value that is not a JWT at all - and an arbitrary string is exactly what these
 * endpoints may be given. A malformed token is not an error at either of them; it
 * simply names no row.
 *
 * Author: John Grimes
 */

/**
 * Extracts the `jti` claim from a compact JWT, without verifying it.
 *
 * @param token - The value the request presented. May be anything at all.
 * @returns The `jti`, or undefined when the value is not a JWT carrying one.
 */
export function unverifiedTokenIdentifier(token: string): string | undefined {
  const parts = token.split(".");
  if (parts.length !== 3) {
    return undefined;
  }
  try {
    const payload = JSON.parse(
      Buffer.from(parts[1] ?? "", "base64url").toString("utf8"),
    ) as { jti?: unknown };
    return typeof payload.jti === "string" && payload.jti.length > 0
      ? payload.jti
      : undefined;
  } catch {
    return undefined;
  }
}
