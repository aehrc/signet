/**
 * Server state, through TanStack Query.
 *
 * Query keys are built here rather than written at call sites, because
 * invalidation depends on them matching: a mutation that invalidated
 * `["clients", tenant]` while the list was cached under `["clients", tenant,
 * endpoint]` would silently show stale data. One builder per resource means the
 * two cannot disagree.
 *
 * The hooks are deliberately thin — a key, a fetch and an invalidation list — and
 * hold no logic of their own. Everything worth testing lives in `./paths.js`,
 * `./errors.js` and the form modules, as plain functions.
 */

import {
  useMutation,
  useQuery,
  useQueryClient,
  type QueryKey,
} from "@tanstack/react-query";

import { get, post, put, remove } from "./client.js";
import {
  auditPath,
  clientPath,
  endpointPath,
  endUserPath,
  PRESETS_PATH,
  SESSION_PATH,
  tenantPath,
  type AuditQuery,
} from "./paths.js";
import { getField, patchField, postField } from "./unwrap.js";

import type {
  ApiTokenView,
  AuditPage,
  ClientRequestView,
  ClientView,
  EndpointKeyView,
  EndpointView,
  EndUserView,
  LaunchSimulationView,
  MemberView,
  PolicyView,
  PresetView,
  SessionView,
  SimulationView,
} from "./types.js";

/** Every query key the console uses, so invalidation cannot miss one. */
export const keys = {
  session: (): QueryKey => ["session"],
  presets: (): QueryKey => ["presets"],
  tenant: (tenant: string): QueryKey => ["tenant", tenant],
  members: (tenant: string): QueryKey => ["members", tenant],
  apiTokens: (tenant: string): QueryKey => ["api-tokens", tenant],
  endpoints: (tenant: string): QueryKey => ["endpoints", tenant],
  endpoint: (tenant: string, endpoint: string): QueryKey => [
    "endpoint",
    tenant,
    endpoint,
  ],
  keys: (tenant: string, endpoint: string): QueryKey => [
    "keys",
    tenant,
    endpoint,
  ],
  clients: (tenant: string, endpoint: string): QueryKey => [
    "clients",
    tenant,
    endpoint,
  ],
  client: (tenant: string, endpoint: string, clientId: string): QueryKey => [
    "client",
    tenant,
    endpoint,
    clientId,
  ],
  users: (tenant: string, endpoint: string): QueryKey => [
    "users",
    tenant,
    endpoint,
  ],
  policies: (tenant: string, endpoint: string): QueryKey => [
    "policies",
    tenant,
    endpoint,
  ],
  clientRequests: (tenant: string, endpoint: string): QueryKey => [
    "client-requests",
    tenant,
    endpoint,
  ],
  audit: (tenant: string, query: AuditQuery): QueryKey => [
    "audit",
    tenant,
    query,
  ],
} as const;

/**
 * Reads the current session.
 *
 * `retry: false` because a 401 is an answer, not a failure to reach the server:
 * retrying it three times delays the sign-in page for no benefit.
 */
export function useSession() {
  return useQuery({
    queryKey: keys.session(),
    queryFn: async ({ signal }) => await get<SessionView>(SESSION_PATH, signal),
    retry: false,
    staleTime: 60_000,
  });
}

/** Signs in. */
export function useSignIn() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (credentials: {
      email: string;
      password: string;
      totp?: string;
    }) => await post<SessionView>(SESSION_PATH, credentials),
    onSuccess: (session) => {
      // Seeded rather than invalidated: the response *is* the session, and a
      // refetch would put a loading state between signing in and seeing the
      // console.
      client.setQueryData(keys.session(), session);
    },
  });
}

/** Signs out, and forgets everything that was read while signed in. */
export function useSignOut() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      await remove(SESSION_PATH);
    },
    onSuccess: async () => {
      // The whole cache, not just the session: everything in it was read with a
      // credential that no longer exists, and some of it names other people.
      client.clear();
      await client.invalidateQueries();
    },
  });
}

/** The policy starting points this deployment ships. */
export function usePresets() {
  return useQuery({
    queryKey: keys.presets(),
    queryFn: async ({ signal }) =>
      await getField<"presets", readonly PresetView[]>(
        PRESETS_PATH,
        "presets",
        signal,
      ),
    // Static for the lifetime of the deployment; refetching is pure waste.
    staleTime: Number.POSITIVE_INFINITY,
  });
}

/** The tenant's endpoints. */
export function useEndpoints(tenant: string) {
  return useQuery({
    queryKey: keys.endpoints(tenant),
    queryFn: async ({ signal }) =>
      await getField<"endpoints", readonly EndpointView[]>(
        tenantPath(tenant, "/endpoints"),
        "endpoints",
        signal,
      ),
  });
}

/** One endpoint. */
export function useEndpoint(tenant: string, endpoint: string) {
  return useQuery({
    queryKey: keys.endpoint(tenant, endpoint),
    queryFn: async ({ signal }) =>
      await getField<"endpoint", EndpointView>(
        endpointPath(tenant, endpoint),
        "endpoint",
        signal,
      ),
  });
}

/** Creates an endpoint. */
export function useCreateEndpoint(tenant: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (body: unknown) =>
      await postField<"endpoint", EndpointView>(
        tenantPath(tenant, "/endpoints"),
        "endpoint",
        body,
      ),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: keys.endpoints(tenant) });
    },
  });
}

/** Edits an endpoint. */
export function useUpdateEndpoint(tenant: string, endpoint: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (body: unknown) =>
      await patchField<"endpoint", EndpointView>(
        endpointPath(tenant, endpoint),
        "endpoint",
        body,
      ),
    onSuccess: async () => {
      await client.invalidateQueries({
        queryKey: keys.endpoint(tenant, endpoint),
      });
      await client.invalidateQueries({ queryKey: keys.endpoints(tenant) });
    },
  });
}

/** Deletes an endpoint. */
export function useDeleteEndpoint(tenant: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (endpoint: string) => {
      await remove(endpointPath(tenant, endpoint));
    },
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: keys.endpoints(tenant) });
    },
  });
}

/** The endpoint's signing keys. */
export function useEndpointKeys(tenant: string, endpoint: string) {
  return useQuery({
    queryKey: keys.keys(tenant, endpoint),
    queryFn: async ({ signal }) =>
      await getField<"keys", readonly EndpointKeyView[]>(
        endpointPath(tenant, endpoint, "/keys"),
        "keys",
        signal,
      ),
  });
}

/** Generates, promotes or retires a signing key. */
export function useKeyAction(tenant: string, endpoint: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (
      action:
        | { readonly kind: "generate"; readonly algorithm: string }
        | { readonly kind: "promote" }
        | { readonly kind: "retire"; readonly kid: string },
    ) => {
      if (action.kind === "generate") {
        await post(endpointPath(tenant, endpoint, "/keys"), {
          algorithm: action.algorithm,
        });
        return;
      }
      if (action.kind === "promote") {
        await post(endpointPath(tenant, endpoint, "/keys/promote"));
        return;
      }
      await post(
        endpointPath(
          tenant,
          endpoint,
          `/keys/${encodeURIComponent(action.kid)}/retire`,
        ),
      );
    },
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: keys.keys(tenant, endpoint) });
    },
  });
}

/** The endpoint's clients. */
export function useClients(tenant: string, endpoint: string) {
  return useQuery({
    queryKey: keys.clients(tenant, endpoint),
    queryFn: async ({ signal }) =>
      await getField<"clients", readonly ClientView[]>(
        endpointPath(tenant, endpoint, "/clients"),
        "clients",
        signal,
      ),
  });
}

/** One client. */
export function useClient(tenant: string, endpoint: string, clientId: string) {
  return useQuery({
    queryKey: keys.client(tenant, endpoint, clientId),
    queryFn: async ({ signal }) =>
      await getField<"client", ClientView>(
        clientPath(tenant, endpoint, clientId),
        "client",
        signal,
      ),
  });
}

/** What a creation or rotation returns: the client, and the secret shown once. */
export interface ClientWithSecret {
  readonly client: ClientView;
  readonly secret?: string;
}

/** Registers a client. */
export function useCreateClient(tenant: string, endpoint: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (body: unknown) =>
      await post<ClientWithSecret>(
        endpointPath(tenant, endpoint, "/clients"),
        body,
      ),
    onSuccess: async () => {
      await client.invalidateQueries({
        queryKey: keys.clients(tenant, endpoint),
      });
    },
  });
}

/** Edits a client. */
export function useUpdateClient(
  tenant: string,
  endpoint: string,
  clientId: string,
) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (body: unknown) =>
      await patchField<"client", ClientView>(
        clientPath(tenant, endpoint, clientId),
        "client",
        body,
      ),
    onSuccess: async () => {
      await client.invalidateQueries({
        queryKey: keys.client(tenant, endpoint, clientId),
      });
      await client.invalidateQueries({
        queryKey: keys.clients(tenant, endpoint),
      });
    },
  });
}

/** Rotates a client secret. */
export function useRotateSecret(
  tenant: string,
  endpoint: string,
  clientId: string,
) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async () =>
      await post<ClientWithSecret>(
        clientPath(tenant, endpoint, clientId, "/secret"),
      ),
    onSuccess: async () => {
      await client.invalidateQueries({
        queryKey: keys.client(tenant, endpoint, clientId),
      });
    },
  });
}

/** Deletes a client. */
export function useDeleteClient(tenant: string, endpoint: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (clientId: string) => {
      await remove(clientPath(tenant, endpoint, clientId));
    },
    onSuccess: async () => {
      await client.invalidateQueries({
        queryKey: keys.clients(tenant, endpoint),
      });
    },
  });
}

/** The endpoint's users and personas. */
export function useEndUsers(tenant: string, endpoint: string) {
  return useQuery({
    queryKey: keys.users(tenant, endpoint),
    queryFn: async ({ signal }) =>
      await getField<"users", readonly EndUserView[]>(
        endpointPath(tenant, endpoint, "/users"),
        "users",
        signal,
      ),
  });
}

/** Creates a user or persona. */
export function useCreateEndUser(tenant: string, endpoint: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (body: unknown) =>
      await postField<"user", EndUserView>(
        endpointPath(tenant, endpoint, "/users"),
        "user",
        body,
      ),
    onSuccess: async () => {
      await client.invalidateQueries({
        queryKey: keys.users(tenant, endpoint),
      });
    },
  });
}

/** Edits a user, including enabling and disabling. */
export function useUpdateEndUser(tenant: string, endpoint: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (change: {
      readonly userId: string;
      readonly body: unknown;
    }) =>
      await patchField<"user", EndUserView>(
        endUserPath(tenant, endpoint, change.userId),
        "user",
        change.body,
      ),
    onSuccess: async () => {
      await client.invalidateQueries({
        queryKey: keys.users(tenant, endpoint),
      });
    },
  });
}

/** Deletes a user. */
export function useDeleteEndUser(tenant: string, endpoint: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (userId: string) => {
      await remove(endUserPath(tenant, endpoint, userId));
    },
    onSuccess: async () => {
      await client.invalidateQueries({
        queryKey: keys.users(tenant, endpoint),
      });
    },
  });
}

/** The endpoint's policy versions. */
export function usePolicies(tenant: string, endpoint: string) {
  return useQuery({
    queryKey: keys.policies(tenant, endpoint),
    queryFn: async ({ signal }) =>
      await getField<"policies", readonly PolicyView[]>(
        endpointPath(tenant, endpoint, "/policies"),
        "policies",
        signal,
      ),
  });
}

/** Creates a policy version, optionally publishing it. */
export function useCreatePolicy(tenant: string, endpoint: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      readonly document: unknown;
      readonly note?: string;
      readonly publish?: boolean;
    }) =>
      await postField<"policy", PolicyView>(
        endpointPath(tenant, endpoint, "/policies"),
        "policy",
        body,
      ),
    onSuccess: async () => {
      await client.invalidateQueries({
        queryKey: keys.policies(tenant, endpoint),
      });
    },
  });
}

/** Publishes an existing version. */
export function usePublishPolicy(tenant: string, endpoint: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (version: number) =>
      await postField<"policy", PolicyView>(
        endpointPath(tenant, endpoint, `/policies/${String(version)}/publish`),
        "policy",
      ),
    onSuccess: async () => {
      await client.invalidateQueries({
        queryKey: keys.policies(tenant, endpoint),
      });
    },
  });
}

/**
 * Simulates an issuance.
 *
 * A mutation rather than a query despite changing nothing on the server: it is
 * driven by an editor whose input is not a cache key, and running it should be the
 * editor's decision rather than a consequence of a key changing.
 */
export function useSimulate(tenant: string, endpoint: string) {
  return useMutation({
    mutationFn: async (body: unknown) =>
      await post<SimulationView>(
        endpointPath(tenant, endpoint, "/policies/simulate"),
        body,
      ),
  });
}

/** The endpoint's registration requests. */
export function useClientRequests(tenant: string, endpoint: string) {
  return useQuery({
    queryKey: keys.clientRequests(tenant, endpoint),
    queryFn: async ({ signal }) =>
      await getField<"requests", readonly ClientRequestView[]>(
        endpointPath(tenant, endpoint, "/client-requests"),
        "requests",
        signal,
      ),
  });
}

/** Approves or rejects a registration request. */
export function useDecideClientRequest(tenant: string, endpoint: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (decision: {
      readonly requestId: string;
      readonly approve: boolean;
      readonly decisionNote?: string;
    }) =>
      await post<{ secret?: string; client?: ClientView }>(
        endpointPath(
          tenant,
          endpoint,
          `/client-requests/${encodeURIComponent(decision.requestId)}/${
            decision.approve ? "approve" : "reject"
          }`,
        ),
        decision.decisionNote === undefined
          ? {}
          : { decisionNote: decision.decisionNote },
      ),
    onSuccess: async () => {
      await client.invalidateQueries({
        queryKey: keys.clientRequests(tenant, endpoint),
      });
      await client.invalidateQueries({
        queryKey: keys.clients(tenant, endpoint),
      });
    },
  });
}

/** Mints a launch handle from the console. */
export function useSimulateLaunch(tenant: string, endpoint: string) {
  return useMutation({
    mutationFn: async (body: unknown) =>
      await post<LaunchSimulationView>(
        endpointPath(tenant, endpoint, "/launch"),
        body,
      ),
  });
}

/** The tenant's members. */
export function useMembers(tenant: string) {
  return useQuery({
    queryKey: keys.members(tenant),
    queryFn: async ({ signal }) =>
      await getField<"members", readonly MemberView[]>(
        tenantPath(tenant, "/members"),
        "members",
        signal,
      ),
  });
}

/** Grants or changes a membership. */
export function useSetMemberRole(tenant: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      readonly email: string;
      readonly role: string;
    }) =>
      await put<{ member: MemberView }>(tenantPath(tenant, "/members"), body),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: keys.members(tenant) });
    },
  });
}

/** Removes a membership. */
export function useRemoveMember(tenant: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (adminUserId: string) => {
      await remove(
        tenantPath(tenant, `/members/${encodeURIComponent(adminUserId)}`),
      );
    },
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: keys.members(tenant) });
    },
  });
}

/** The tenant's personal access tokens. */
export function useApiTokens(tenant: string) {
  return useQuery({
    queryKey: keys.apiTokens(tenant),
    queryFn: async ({ signal }) =>
      await getField<"tokens", readonly ApiTokenView[]>(
        tenantPath(tenant, "/api-tokens"),
        "tokens",
        signal,
      ),
  });
}

/** Mints a personal access token. The value is in the response, once. */
export function useCreateApiToken(tenant: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      readonly name: string;
      readonly role: string;
      readonly expiresAt?: string;
    }) =>
      await post<{ token: ApiTokenView; value: string }>(
        tenantPath(tenant, "/api-tokens"),
        body,
      ),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: keys.apiTokens(tenant) });
    },
  });
}

/** Revokes a personal access token. */
export function useRevokeApiToken(tenant: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (tokenId: string) => {
      await remove(
        tenantPath(tenant, `/api-tokens/${encodeURIComponent(tokenId)}`),
      );
    },
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: keys.apiTokens(tenant) });
    },
  });
}

/** One page of the audit trail. */
export function useAudit(tenant: string, query: AuditQuery) {
  return useQuery({
    queryKey: keys.audit(tenant, query),
    queryFn: async ({ signal }) =>
      await get<AuditPage>(auditPath(tenant, query), signal),
  });
}
