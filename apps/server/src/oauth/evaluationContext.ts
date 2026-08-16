/**
 * The context a policy is evaluated against, built in one place.
 *
 * Two callers need one: the issuance chokepoint, which evaluates a policy for
 * every token any grant produces, and the subject resolver, which evaluates the
 * same endpoint's policy for the short-lived token it searches the FHIR server
 * with. The endpoint half of that context - the tenant slug, the endpoint slug,
 * the issuer and the audience - is identical in both, and it is exactly the part
 * a policy's templates read: a second construction of it is a second thing that
 * could name the wrong audience, and a token whose `aud` is wrong is refused by
 * the resource server with no explanation either side can act on.
 *
 * Author: John Grimes
 */

import type { ResolvedIssuerContext } from "../context.js";
import type {
  EvaluationClient,
  EvaluationContext,
  EvaluationUser,
  GrantType,
  LaunchContext,
  Scope,
} from "@signet/core";

/** What an evaluation is about, beyond the endpoint it happens on. */
export interface EvaluationSubject {
  readonly issuerContext: ResolvedIssuerContext;
  readonly client: EvaluationClient;
  /** Null for a backend service or a self-issued token, which has no end user. */
  readonly user: EvaluationUser | null;
  /** Scopes to evaluate, already parsed and normalised. */
  readonly requested: readonly Scope[];
  readonly launchContext: LaunchContext;
  readonly grantType: GrantType;
}

/**
 * Builds the context a policy is evaluated against.
 *
 * @param subject - The endpoint, the client, the user if there is one, the
 *   scopes being asked for and the launch context they are asked in.
 * @returns The evaluation context, for `evaluatePolicy` and for the claim
 *   assembly that follows it. The two must be handed the same value, which is
 *   why this returns one rather than being called twice.
 * @example
 * ```ts
 * const evaluationContext = buildEvaluationContext({
 *   issuerContext,
 *   client,
 *   user: null,
 *   requested,
 *   launchContext: {},
 *   grantType: "client_credentials",
 * });
 * ```
 */
export function buildEvaluationContext(
  subject: EvaluationSubject,
): EvaluationContext {
  const { issuerContext } = subject;
  return {
    endpoint: {
      tenantSlug: issuerContext.tenant.slug,
      slug: issuerContext.endpoint.slug,
      issuer: issuerContext.issuer,
      fhirBaseUrl: issuerContext.endpoint.fhirBaseUrl,
    },
    client: subject.client,
    user: subject.user,
    requested: subject.requested,
    context: subject.launchContext,
    grantType: subject.grantType,
  };
}
