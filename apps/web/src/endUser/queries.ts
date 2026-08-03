/**
 * The end-user surfaces' server state, through TanStack Query.
 *
 * The same reasoning as the console's: server state belongs in a query cache rather than
 * in an effect that assigns to component state. It also removes the hand-rolled loading
 * and failure bookkeeping from three pages that would each have got it slightly
 * differently.
 *
 * The interaction is a query with `staleTime: 0` and no retry. Its answer is a step in a
 * flow: a refetch is exactly what should happen after each post, and a retry of a refusal
 * would repeat an authorization decision.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  manageSignIn,
  manageSignOut,
  readAuthorizations,
  readInteraction,
  revokeAuthorization,
  submitConsent,
  submitContext,
  submitLogin,
} from "./api.js";

import type { LoginCredentials } from "./api.js";

/** Reads the current step of an authorization. */
export function useInteractionState(
  tenant: string,
  endpoint: string,
  session: string,
) {
  return useQuery({
    queryKey: ["interaction", tenant, endpoint, session],
    queryFn: async () => await readInteraction(tenant, endpoint, session),
    retry: false,
    // Every post returns the next step and seeds this, so there is nothing to gain
    // from treating a previous answer as fresh.
    staleTime: 0,
    refetchOnWindowFocus: false,
  });
}

/**
 * Advances the authorization one step.
 *
 * One mutation for all three posts, because they differ only in which endpoint they
 * call and every one of them returns the same thing: the step the session is now on.
 * The result seeds the query, so the page re-renders from the server's answer rather
 * than from an assumption about what the post did.
 */
export function useAdvanceInteraction(
  tenant: string,
  endpoint: string,
  session: string,
) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (
      step:
        | { readonly kind: "login"; readonly credentials: LoginCredentials }
        | {
            readonly kind: "context";
            readonly chosen: {
              readonly patient?: string;
              readonly encounter?: string;
            };
          }
        | { readonly kind: "consent"; readonly approve: boolean },
    ) => {
      if (step.kind === "login") {
        return await submitLogin(tenant, endpoint, session, step.credentials);
      }
      if (step.kind === "context") {
        return await submitContext(tenant, endpoint, session, step.chosen);
      }
      return await submitConsent(tenant, endpoint, session, step.approve);
    },
    onSuccess: (next) => {
      client.setQueryData(["interaction", tenant, endpoint, session], next);
    },
  });
}

/** Reads what an end user has granted on this endpoint. */
export function useAuthorizations(tenant: string, endpoint: string) {
  return useQuery({
    queryKey: ["authorizations", tenant, endpoint],
    queryFn: async () => await readAuthorizations(tenant, endpoint),
    retry: false,
    refetchOnWindowFocus: false,
  });
}

/** Signs an end user in to the management page. */
export function useManageSignIn(tenant: string, endpoint: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (credentials: LoginCredentials) =>
      await manageSignIn(tenant, endpoint, credentials),
    onSuccess: async () => {
      await client.invalidateQueries({
        queryKey: ["authorizations", tenant, endpoint],
      });
    },
  });
}

/** Signs an end user out, and forgets what was read while they were signed in. */
export function useManageSignOut(tenant: string, endpoint: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      await manageSignOut(tenant, endpoint);
    },
    onSuccess: () => {
      // Removed rather than invalidated: an invalidation would refetch, and the
      // refetch would 401 and briefly render an error where a sign-in form belongs.
      client.removeQueries({ queryKey: ["authorizations", tenant, endpoint] });
    },
  });
}

/** Withdraws one app's access. */
export function useRevokeAuthorization(tenant: string, endpoint: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (clientId: string) =>
      await revokeAuthorization(tenant, endpoint, clientId),
    onSettled: async () => {
      // On settled rather than on success: if the revocation failed, the list must
      // still be reloaded, because what it shows would otherwise be a guess.
      await client.invalidateQueries({
        queryKey: ["authorizations", tenant, endpoint],
      });
    },
  });
}
