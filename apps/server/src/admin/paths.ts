/**
 * The admin API's path shapes.
 *
 * Kept apart from the router so that each resource module can register its own
 * routes against the same patterns without importing the router that mounts it. The
 * patterns are the contract between the route table and the middleware: everything
 * below {@link TENANT_PATH} has a tenant scope in hand, and everything below
 * {@link ENDPOINT_PATH} has it narrowed to one endpoint.
 */

/** Where the admin API is mounted within the application. */
export const ADMIN_BASE_PATH = "/api/v1";

/** Every tenant-scoped path, relative to {@link ADMIN_BASE_PATH}. */
export const TENANT_PATH = "/tenants/:tenantSlug";

/** Every endpoint-scoped path, relative to {@link ADMIN_BASE_PATH}. */
export const ENDPOINT_PATH = `${TENANT_PATH}/endpoints/:endpointSlug`;
