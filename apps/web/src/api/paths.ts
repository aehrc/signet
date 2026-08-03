/**
 * Admin API paths, built in one place.
 *
 * Every slug is percent-encoded on the way in. A tenant or endpoint slug is
 * constrained to lower-case alphanumerics and hyphens by the API, so in practice
 * encoding changes nothing — but a client identifier is not, and neither is an
 * audit filter value. Encoding everything means the rule is "paths are built here",
 * with no exceptions to remember.
 *
 * Pure and tested, because a path built wrongly fails as a 404 that looks like
 * missing data rather than as a mistake.
 */

/** Where the admin API is mounted. */
export const API_BASE = "/api/v1";

/** Escapes one path segment. */
function segment(value: string): string {
  return encodeURIComponent(value);
}

/** The session resource: sign in, sign out, and who am I. */
export const SESSION_PATH = `${API_BASE}/session`;

/** The policy presets this deployment ships. */
export const PRESETS_PATH = `${API_BASE}/presets`;

/** A tenant, and anything under it. */
export function tenantPath(tenant: string, suffix = ""): string {
  return `${API_BASE}/tenants/${segment(tenant)}${suffix}`;
}

/** An endpoint, and anything under it. */
export function endpointPath(
  tenant: string,
  endpoint: string,
  suffix = "",
): string {
  return tenantPath(tenant, `/endpoints/${segment(endpoint)}${suffix}`);
}

/** One registered client. */
export function clientPath(
  tenant: string,
  endpoint: string,
  clientId: string,
  suffix = "",
): string {
  return endpointPath(
    tenant,
    endpoint,
    `/clients/${segment(clientId)}${suffix}`,
  );
}

/** One end user or persona. */
export function endUserPath(
  tenant: string,
  endpoint: string,
  userId: string,
  suffix = "",
): string {
  return endpointPath(tenant, endpoint, `/users/${segment(userId)}${suffix}`);
}

/** What the audit browser is asking for. */
export interface AuditQuery {
  readonly endpointSlug?: string;
  readonly actorType?: string;
  readonly action?: readonly string[];
  readonly from?: string;
  readonly until?: string;
  readonly limit?: number;
  readonly cursor?: string;
}

/**
 * Builds the audit query string.
 *
 * `action` repeats rather than joining with commas, because that is what the API's
 * schema accepts and what an HTML multi-select produces. Empty values are omitted
 * entirely: `?actorType=` would be a filter for the empty string.
 *
 * @param tenant - The tenant whose trail to read.
 * @param query - The filter, as the browser holds it.
 */
export function auditPath(tenant: string, query: AuditQuery = {}): string {
  const parameters = new URLSearchParams();
  const simple: readonly [string, string | number | undefined][] = [
    ["endpointSlug", query.endpointSlug],
    ["actorType", query.actorType],
    ["from", query.from],
    ["until", query.until],
    ["limit", query.limit],
    ["cursor", query.cursor],
  ];
  for (const [name, value] of simple) {
    if (value !== undefined && String(value).length > 0) {
      parameters.set(name, String(value));
    }
  }
  for (const action of query.action ?? []) {
    if (action.length > 0) {
      parameters.append("action", action);
    }
  }

  const search = parameters.toString();
  return tenantPath(
    tenant,
    search.length === 0 ? "/audit" : `/audit?${search}`,
  );
}
