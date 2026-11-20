/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Server state, through TanStack Query.
 *
 * Query keys are built here rather than written at call sites, because
 * invalidation depends on them matching: a mutation that invalidated
 * `["clients", tenant]` while the list was cached under `["clients", tenant,
 * endpoint]` would silently show stale data. One builder per resource means the
 * two cannot disagree.
 *
 * The hooks are deliberately thin - a key, a fetch and an invalidation list - and
 * hold no logic of their own. Everything worth testing lives in `./paths.js`,
 * `./errors.js` and the form modules, as plain functions.
 *
 * Author: John Grimes
 */

import { describeLogoProblem, inspectLogo } from "@signet/core";
import {
  useMutation,
  useQuery,
  useQueryClient,
  type QueryClient,
  type QueryKey,
} from "@tanstack/react-query";

import { get, post, put, remove } from "./client.js";
import {
  auditPath,
  clientPath,
  endpointPath,
  endpointUserPath,
  passkeyPath,
  PASSKEYS_PATH,
  PASSKEY_OPTIONS_PATH,
  PASSKEY_SIGN_IN_OPTIONS_PATH,
  PASSKEY_SIGN_IN_PATH,
  PRESETS_PATH,
  SESSION_PATH,
  tenantPath,
  tenantUserPath,
  type AuditQuery,
} from "./paths.js";
import { getField, patchField, postField } from "./unwrap.js";
import { brandingKey } from "../endUser/queries.js";

import type {
  IdpCheckView,
  IdpConfigView,
  TicketIssuerView,
  TrustAnchorCheckView,
  TrustAnchorView,
  ApiTokenView,
  AuditPage,
  ClientRequestView,
  ClientView,
  EndpointKeyView,
  EndpointEndUserView,
  EndpointView,
  EndUserView,
  InvitationView,
  IssuedInvitationView,
  LaunchSimulationView,
  MemberView,
  PasskeyView,
  PolicyView,
  PresetView,
  SessionView,
  SimulationView,
} from "./types.js";
import type { LogoVariant } from "@signet/core";
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/browser";

/** Every query key the console uses, so invalidation cannot miss one. */
export const keys = {
  session: (): QueryKey => ["session"],
  passkeys: (): QueryKey => ["passkeys"],
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
  idp: (tenant: string, endpoint: string): QueryKey => [
    "idp",
    tenant,
    endpoint,
  ],
  trustAnchor: (tenant: string, endpoint: string): QueryKey => [
    "trust-anchor",
    tenant,
    endpoint,
  ],
  ticketIssuer: (tenant: string, endpoint: string): QueryKey => [
    "ticket-issuer",
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
  users: (tenant: string): QueryKey => ["users", tenant],
  endUser: (tenant: string, userId: string): QueryKey => [
    "user",
    tenant,
    userId,
  ],
  invitation: (tenant: string, userId: string): QueryKey => [
    "invitation",
    tenant,
    userId,
  ],
  /** Every endpoint's view of its users, as a prefix of {@link keys.endpointUsers}. */
  allEndpointUsers: (tenant: string): QueryKey => ["endpoint-users", tenant],
  endpointUsers: (tenant: string, endpoint: string): QueryKey => [
    "endpoint-users",
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

/**
 * The signed-in person's registered passkeys.
 *
 * Not fetched until the dialog is opened - `enabled` is what the caller passes -
 * because most console sessions never open it, and a query that ran on every page
 * load would spend a request per navigation to populate a menu item.
 */
export function usePasskeys(enabled = true) {
  return useQuery({
    queryKey: keys.passkeys(),
    queryFn: async ({ signal }) =>
      await getField<"passkeys", readonly PasskeyView[]>(
        PASSKEYS_PATH,
        "passkeys",
        signal,
      ),
    enabled,
  });
}

/**
 * Asks the server to begin a registration, confirming the password.
 *
 * A mutation rather than a query for two reasons: it writes a challenge row, and it
 * must happen when the person presses the button rather than when a component
 * mounts. What it returns goes straight to the browser's own ceremony.
 */
export function useRegisterPasskeyOptions() {
  return useMutation({
    mutationFn: async (password: string) =>
      await post<PublicKeyCredentialCreationOptionsJSON>(PASSKEY_OPTIONS_PATH, {
        password,
      }),
  });
}

/** Stores the passkey the browser has just created. */
export function useRegisterPasskey() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (registration: {
      readonly name: string | null;
      readonly response: RegistrationResponseJSON;
    }) =>
      await postField<"passkey", PasskeyView>(
        PASSKEYS_PATH,
        "passkey",
        registration,
      ),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: keys.passkeys() });
    },
  });
}

/** Removes a passkey, confirming the password. */
export function useRemovePasskey() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (removal: {
      readonly passkeyId: string;
      readonly password: string;
    }) => {
      await remove(passkeyPath(removal.passkeyId), {
        password: removal.password,
      });
    },
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: keys.passkeys() });
    },
  });
}

/**
 * Signs in with a passkey: both halves of the ceremony, as one action.
 *
 * The two requests are one mutation because they are one thing the person did, and
 * splitting them would put the browser prompt between two pending states the page
 * would have to reconcile. The session is seeded rather than invalidated, for the
 * reason {@link useSignIn} does it.
 */
export function usePasskeySignIn() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (
      ceremony: (
        options: PublicKeyCredentialRequestOptionsJSON,
      ) => Promise<AuthenticationResponseJSON>,
    ) => {
      const options = await post<PublicKeyCredentialRequestOptionsJSON>(
        PASSKEY_SIGN_IN_OPTIONS_PATH,
      );
      return await post<SessionView>(
        PASSKEY_SIGN_IN_PATH,
        await ceremony(options),
      );
    },
    onSuccess: (session) => {
      client.setQueryData(keys.session(), session);
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

/**
 * The endpoint's upstream identity provider, or null when it federates to none.
 *
 * Null rather than an error: an endpoint with local accounts is the normal case,
 * and a 404 for it would have every caller unpicking a failure that is not one.
 */
export function useIdpConfig(tenant: string, endpoint: string) {
  return useQuery({
    queryKey: keys.idp(tenant, endpoint),
    queryFn: async ({ signal }) =>
      await getField<"idp", IdpConfigView | null>(
        endpointPath(tenant, endpoint, "/idp"),
        "idp",
        signal,
      ),
  });
}

/** Saves or removes the upstream identity provider. */
export function useIdpAction(tenant: string, endpoint: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (
      action:
        | { readonly kind: "save"; readonly config: Record<string, unknown> }
        | { readonly kind: "remove" },
    ) => {
      if (action.kind === "remove") {
        await remove(endpointPath(tenant, endpoint, "/idp"));
        return;
      }
      await put(endpointPath(tenant, endpoint, "/idp"), action.config);
    },
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: keys.idp(tenant, endpoint) });
    },
  });
}

/**
 * Asks the server to fetch the provider's discovery document and report on it.
 *
 * A mutation rather than a query, because it is an action an operator takes: it
 * makes an outbound request, and it should happen when they ask rather than
 * whenever a component mounts.
 */
export function useIdpCheck(tenant: string, endpoint: string) {
  return useMutation({
    mutationFn: async () =>
      await post<IdpCheckView>(endpointPath(tenant, endpoint, "/idp/check")),
  });
}

/**
 * The endpoint's trust anchor, or null when it accepts no registrations.
 *
 * Null rather than an error, as the identity provider's is: refusing every
 * registration is the default and the normal case, not a failure to unpick.
 */
export function useTrustAnchor(tenant: string, endpoint: string) {
  return useQuery({
    queryKey: keys.trustAnchor(tenant, endpoint),
    queryFn: async ({ signal }) =>
      await getField<"anchor", TrustAnchorView | null>(
        endpointPath(tenant, endpoint, "/trust/anchor"),
        "anchor",
        signal,
      ),
  });
}

/** Saves or removes the endpoint's trust anchor. */
export function useTrustAnchorAction(tenant: string, endpoint: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (
      action:
        | { readonly kind: "save"; readonly anchor: Record<string, unknown> }
        | { readonly kind: "remove" },
    ) => {
      if (action.kind === "remove") {
        await remove(endpointPath(tenant, endpoint, "/trust/anchor"));
        return;
      }
      await put(endpointPath(tenant, endpoint, "/trust/anchor"), action.anchor);
    },
    onSuccess: async () => {
      await client.invalidateQueries({
        queryKey: keys.trustAnchor(tenant, endpoint),
      });
      // The discovery document changes with the rule, and the endpoint page
      // renders what it advertises.
      await client.invalidateQueries({
        queryKey: keys.endpoint(tenant, endpoint),
      });
    },
  });
}

/**
 * Asks the server to fetch the anchor's published keys and report on them.
 *
 * A mutation rather than a query, for the reason the identity provider's check is
 * one: it makes an outbound request, and that should happen when an operator asks
 * rather than whenever a component mounts.
 */
export function useTrustAnchorCheck(tenant: string, endpoint: string) {
  return useMutation({
    mutationFn: async () =>
      await post<TrustAnchorCheckView>(
        endpointPath(tenant, endpoint, "/trust/anchor/check"),
      ),
  });
}

/**
 * The endpoint's permission ticket issuer, or null when it exchanges none.
 *
 * Null rather than an error, as the trust anchor's is: refusing the exchange
 * grant is the default and the normal case, not a failure to unpick.
 *
 * Not fetched when `enabled` is false, which is how an OAuth endpoint - where the
 * API refuses the route, because ticket exchange is SMART-only - avoids asking.
 */
export function useTicketIssuer(
  tenant: string,
  endpoint: string,
  enabled: boolean,
) {
  return useQuery({
    queryKey: keys.ticketIssuer(tenant, endpoint),
    queryFn: async ({ signal }) =>
      await getField<"ticketIssuer", TicketIssuerView | null>(
        endpointPath(tenant, endpoint, "/trust/ticket-issuer"),
        "ticketIssuer",
        signal,
      ),
    enabled,
  });
}

/** Saves or removes the endpoint's permission ticket issuer. */
export function useTicketIssuerAction(tenant: string, endpoint: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (
      action:
        | { readonly kind: "save"; readonly rule: Record<string, unknown> }
        | { readonly kind: "remove" },
    ) => {
      const path = endpointPath(tenant, endpoint, "/trust/ticket-issuer");
      await (action.kind === "remove" ? remove(path) : put(path, action.rule));
    },
    onSuccess: async () => {
      await client.invalidateQueries({
        queryKey: keys.ticketIssuer(tenant, endpoint),
      });
      // The advertised ticket types change with the rule, and the endpoint page
      // renders what it advertises.
      await client.invalidateQueries({
        queryKey: keys.endpoint(tenant, endpoint),
      });
    },
  });
}

/**
 * Asks the server to fetch the ticket issuer's published keys and report on them.
 *
 * A mutation for the reason the anchor's check is one: it makes an outbound
 * request, and that should happen when an operator asks rather than whenever a
 * component mounts.
 */
export function useTicketIssuerCheck(tenant: string, endpoint: string) {
  return useMutation({
    mutationFn: async () =>
      await post<TrustAnchorCheckView>(
        endpointPath(tenant, endpoint, "/trust/ticket-issuer/check"),
      ),
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

/**
 * Refreshes everything that shows an account after it changed.
 *
 * The tenant's list, the account's own page, and every endpoint's view of its users:
 * the policy simulator lists an account by its display name, and an account is listed
 * by each endpoint it has access to, so a change to one is a change to all of them.
 */
async function invalidateEndUser(
  client: QueryClient,
  tenant: string,
  userId: string,
): Promise<void> {
  await Promise.all([
    client.invalidateQueries({ queryKey: keys.endUser(tenant, userId) }),
    client.invalidateQueries({ queryKey: keys.users(tenant) }),
    client.invalidateQueries({ queryKey: keys.allEndpointUsers(tenant) }),
  ]);
}

/** The tenant's users and personas. */
export function useEndUsers(tenant: string) {
  return useQuery({
    queryKey: keys.users(tenant),
    queryFn: async ({ signal }) =>
      await getField<"users", readonly EndUserView[]>(
        tenantPath(tenant, "/users"),
        "users",
        signal,
      ),
  });
}

/**
 * The accounts with access to one endpoint, as that endpoint sees them.
 *
 * What the policy simulator offers, so it cannot pick an account the endpoint would
 * refuse to sign in.
 */
export function useEndpointUsers(tenant: string, endpoint: string) {
  return useQuery({
    queryKey: keys.endpointUsers(tenant, endpoint),
    queryFn: async ({ signal }) =>
      await getField<"users", readonly EndpointEndUserView[]>(
        endpointPath(tenant, endpoint, "/users"),
        "users",
        signal,
      ),
  });
}

/** One end user or persona. */
export function useEndUser(tenant: string, userId: string) {
  return useQuery({
    queryKey: keys.endUser(tenant, userId),
    queryFn: async ({ signal }) =>
      await getField<"user", EndUserView>(
        tenantUserPath(tenant, userId),
        "user",
        signal,
      ),
  });
}

/** Creates a user or persona in the tenant, with access to no endpoint yet. */
export function useCreateEndUser(tenant: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (body: unknown) =>
      await postField<"user", EndUserView>(
        tenantPath(tenant, "/users"),
        "user",
        body,
      ),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: keys.users(tenant) });
    },
  });
}

/** Edits a user, including enabling and disabling. */
export function useUpdateEndUser(tenant: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (change: {
      readonly userId: string;
      readonly body: unknown;
    }) =>
      await patchField<"user", EndUserView>(
        tenantUserPath(tenant, change.userId),
        "user",
        change.body,
      ),
    onSuccess: async (_user, change) => {
      await invalidateEndUser(client, tenant, change.userId);
    },
  });
}

/**
 * Sets a user's password.
 *
 * Its own hook rather than a field on the patch, mirroring the API: replacing a
 * credential is a separate operation with its own audit event. The account is
 * refreshed because its summary says whether a password is set.
 */
export function useSetEndUserPassword(tenant: string, userId: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (password: string) => {
      await post<void>(tenantUserPath(tenant, userId, "/password"), {
        password,
      });
    },
    onSuccess: async () => {
      await invalidateEndUser(client, tenant, userId);
    },
  });
}

/** Deletes a user. */
export function useDeleteEndUser(tenant: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (userId: string) => {
      await remove(tenantUserPath(tenant, userId));
    },
    onSuccess: async (_result, userId) => {
      // The detail query is removed rather than invalidated: the row is gone, and
      // refetching it would answer 404 into a page the browser is leaving.
      client.removeQueries({ queryKey: keys.endUser(tenant, userId) });
      await Promise.all([
        client.invalidateQueries({ queryKey: keys.users(tenant) }),
        client.invalidateQueries({ queryKey: keys.allEndpointUsers(tenant) }),
      ]);
    },
  });
}

/**
 * Gives a user access to an endpoint, or changes the access they have.
 *
 * The same PUT does both: an empty body gives access and leaves the fields alone,
 * and a body naming `fhirUserReference` or `defaultContext` sets them. The response
 * is the whole account, which seeds its page before the refresh.
 */
export function useGrantEndpointAccess(tenant: string, userId: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (change: {
      readonly endpoint: string;
      readonly body: Readonly<Record<string, unknown>>;
    }) => {
      const response = await put<{ readonly user: EndUserView }>(
        endpointUserPath(tenant, change.endpoint, userId),
        change.body,
      );
      return response.user;
    },
    onSuccess: async (user) => {
      client.setQueryData(keys.endUser(tenant, userId), user);
      await invalidateEndUser(client, tenant, userId);
    },
  });
}

/**
 * Withdraws a user's access to an endpoint.
 *
 * The server deletes their consents and sessions there and refuses their refresh
 * tokens there from then on. Refreshed on settled rather than on success, so that a
 * refusal still leaves the page showing what the server holds rather than a guess.
 */
export function useRevokeEndpointAccess(tenant: string, userId: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (endpoint: string) => {
      await remove(endpointUserPath(tenant, endpoint, userId));
    },
    onSettled: async () => {
      await invalidateEndUser(client, tenant, userId);
    },
  });
}

/** A user's outstanding invitation, or null when there is none. */
export function useEndUserInvitation(tenant: string, userId: string) {
  return useQuery({
    queryKey: keys.invitation(tenant, userId),
    queryFn: async ({ signal }) =>
      await getField<"invitation", InvitationView | null>(
        tenantUserPath(tenant, userId, "/invitation"),
        "invitation",
        signal,
      ),
  });
}

/** Makes a new invitation for a user, replacing any outstanding one. */
export function useCreateInvitation(tenant: string, userId: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async () =>
      await postField<"invitation", IssuedInvitationView>(
        tenantUserPath(tenant, userId, "/invitation"),
        "invitation",
      ),
    onSettled: async () => {
      // Settled rather than succeeded: a refusal may still have replaced the old
      // link, and what the panel shows must not be a guess.
      await client.invalidateQueries({
        queryKey: keys.invitation(tenant, userId),
      });
    },
  });
}

/** Cancels a user's outstanding invitation, so its link stops working. */
export function useCancelInvitation(tenant: string, userId: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      await remove(tenantUserPath(tenant, userId, "/invitation"));
    },
    onSettled: async () => {
      await client.invalidateQueries({
        queryKey: keys.invitation(tenant, userId),
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

/**
 * Uploads one of the tenant's logos.
 *
 * The file is checked here with the same `inspectLogo` the server applies, so a file
 * that would be refused is refused at once, in the same words, without a round trip.
 * What is sent is the file's bytes typed as what they were found to be, not as
 * whatever the browser guessed from its extension.
 */
export function useUploadLogo(tenant: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (upload: {
      readonly variant: LogoVariant;
      readonly file: Blob;
    }) => {
      const bytes = new Uint8Array(await upload.file.arrayBuffer());
      const inspection = inspectLogo(bytes);
      if (!inspection.ok) {
        throw new Error(describeLogoProblem(inspection.problem));
      }
      await put<unknown>(
        tenantPath(tenant, `/logo/${upload.variant}`),
        new Blob([bytes], { type: inspection.mediaType }),
      );
    },
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: brandingKey(tenant) });
    },
  });
}

/** Removes one of the tenant's logos; removing the logo removes its dark variant. */
export function useRemoveLogo(tenant: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (variant: LogoVariant) => {
      await remove(tenantPath(tenant, `/logo/${variant}`));
    },
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: brandingKey(tenant) });
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
