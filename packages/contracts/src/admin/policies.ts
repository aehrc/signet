/**
 * Policy versions and the simulator.
 *
 * The simulate request is the interesting one. It is the console's inner loop —
 * every keystroke in the rule builder re-renders a decoded token — and it takes a
 * policy document *in the request* rather than a stored version, so an operator
 * can see what an unsaved edit would produce. That is also why it identifies the
 * client and user by their existing rows rather than accepting invented ones: a
 * simulation that let the caller describe an arbitrary user would answer a
 * question nobody asked, and would be a way to probe what a policy does with
 * roles the tenant has not defined.
 */

import { z } from "zod";

import { launchContextInputSchema } from "../launchContext.js";
import { policyDocumentSchema } from "../policy.js";
import { scopeStringSchema } from "../primitives.js";

/** Creating a policy version. */
export const policyVersionCreateSchema = z.object({
  document: policyDocumentSchema,
  /** What changed and why. Shown beside the version in the history. */
  note: z.string().max(2000).optional(),
  /** Publish immediately, rather than leaving the version as a draft. */
  publish: z.boolean().optional(),
});

/** The launch context a simulation runs with. */
export const simulationContextSchema = launchContextInputSchema;

/** A policy simulation. */
export const policySimulationSchema = z.object({
  /**
   * The document to evaluate.
   *
   * Absent means the endpoint's published policy, which is how the console shows
   * what a client is getting right now rather than what an edit would give it.
   */
  document: policyDocumentSchema.optional(),
  /** The client to simulate as; must be registered on the endpoint. */
  clientId: z.string().min(1).max(128),
  /** The end user to simulate as. Omit for a `client_credentials` grant. */
  endUserId: z.string().uuid().optional(),
  requestedScopes: scopeStringSchema,
  grantType: z
    .enum(["authorization_code", "client_credentials", "refresh_token"])
    .optional(),
  context: simulationContextSchema.optional(),
});

export type PolicyVersionCreate = z.infer<typeof policyVersionCreateSchema>;
export type PolicySimulation = z.infer<typeof policySimulationSchema>;
export type SimulationContext = z.infer<typeof simulationContextSchema>;
