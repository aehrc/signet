/**
 * The console's admin API client.
 *
 * The request itself lives in `./request.js`, shared with the end-user surfaces. What is
 * here is the vocabulary the console calls it with: five verbs, so a query hook reads as
 * `get(path)` rather than as a fetch with options.
 *
 * The admin API's refusal bodies already carry `message`, so no error normalisation is
 * needed - that parameter exists for the OAuth endpoints, which answer in RFC 6749's
 * shape instead.
 *
 * Author: John Grimes
 */

import { requestJson } from "./request.js";

/** Reads a resource. */
export async function get<T>(path: string, signal?: AbortSignal): Promise<T> {
  return await requestJson<T>(path, {
    ...(signal === undefined ? {} : { signal }),
  });
}

/** Creates a resource, or performs an action on one. */
export async function post<T>(path: string, body?: unknown): Promise<T> {
  return await requestJson<T>(path, {
    method: "POST",
    ...(body === undefined ? {} : { body }),
  });
}

/** Edits a resource. */
export async function patch<T>(path: string, body: unknown): Promise<T> {
  return await requestJson<T>(path, { method: "PATCH", body });
}

/** Replaces or upserts a resource. */
export async function put<T>(path: string, body: unknown): Promise<T> {
  return await requestJson<T>(path, { method: "PUT", body });
}

/**
 * Deletes a resource.
 *
 * A body is unusual on a `DELETE` and is here for one case: removing a passkey has
 * to carry the password that authorises it, and the alternative - a password in the
 * query string - would put a credential in the server's access log.
 */
export async function remove(path: string, body?: unknown): Promise<void> {
  await requestJson<void>(path, {
    method: "DELETE",
    ...(body === undefined ? {} : { body }),
  });
}
