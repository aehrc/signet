/**
 * Driving the admin API the way the console and a script do.
 *
 * Two credentials, one set of helpers. Every suite that exercises a route is
 * expected to run at least one case with each - a session cookie and a personal
 * access token reach their tenant scope by different routes, and a route that works
 * for one and not the other is a bug the console would never find.
 *
 * Author: John Grimes
 */

import type { TestStack } from "./harness.js";

/** How a request authenticates itself. */
export type AdminCredential =
  { readonly cookie: string } | { readonly bearer: string };

/** Builds the headers that present a credential. */
export function credentialHeaders(
  credential: AdminCredential | undefined,
): Record<string, string> {
  if (credential === undefined) {
    return {};
  }
  return "cookie" in credential
    ? { cookie: credential.cookie }
    : { authorization: `Bearer ${credential.bearer}` };
}

/** The admin API path for one of the fixture tenant's resources. */
export function tenantPath(stack: TestStack, suffix = ""): string {
  return `/api/v1/tenants/${stack.tenant.slug}${suffix}`;
}

/** The admin API path for one of the fixture endpoint's resources. */
export function endpointPath(stack: TestStack, suffix = ""): string {
  return tenantPath(stack, `/endpoints/${stack.endpoint.slug}${suffix}`);
}

/** What an admin API request should carry. */
export interface AdminRequestOptions {
  readonly credential?: AdminCredential;
  /** Serialised as JSON. Omit for a request with no body. */
  readonly body?: unknown;
}

/**
 * Makes an admin API request.
 *
 * @param stack - The fixture stack.
 * @param method - The HTTP method.
 * @param path - An absolute path, usually from {@link tenantPath}.
 * @param options - The credential and body.
 */
export async function adminRequest(
  stack: TestStack,
  method: string,
  path: string,
  options: AdminRequestOptions = {},
): Promise<Response> {
  return await stack.app.request(path, {
    method,
    headers: {
      ...credentialHeaders(options.credential),
      ...(options.body === undefined
        ? {}
        : { "content-type": "application/json" }),
    },
    ...(options.body === undefined
      ? {}
      : { body: JSON.stringify(options.body) }),
  });
}

/**
 * Makes an admin API request and returns its parsed body.
 *
 * @throws {Error} When the status is not the one expected, with the body in the
 *   message - a failed assertion on a field of `undefined` says much less.
 */
export async function adminJson<T>(
  stack: TestStack,
  method: string,
  path: string,
  options: AdminRequestOptions & { readonly expect?: number } = {},
): Promise<T> {
  const response = await adminRequest(stack, method, path, options);
  const expected = options.expect ?? 200;
  if (response.status !== expected) {
    throw new Error(
      `${method} ${path} expected ${String(expected)}, got ${String(response.status)}: ${await response.text()}`,
    );
  }
  return (await response.json()) as T;
}
