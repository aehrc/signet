/**
 * Turning a permission ticket's subject identifier into a patient.
 *
 * A ticket names its subject the way one system names a person to another - by
 * identifier, an IHI in the connectathon programme - and the token Signet mints
 * from it carries a patient launch context, which names a patient the way *this*
 * FHIR server names one: by resource id. Nothing but the server itself can join
 * those two, so this module asks it, with one search.
 *
 * **Exactly one match, or nothing.** Zero is `subject-unknown` and more than one
 * is `subject-ambiguous`, and they are different because an operator does
 * different things about them: an unknown subject is a record that is not there,
 * and an ambiguous one is a duplicate on the server that has to be fixed. Picking
 * one of two would mint a token against a guessed patient, which is the failure
 * this whole grant is built to avoid.
 *
 * **The identifier system is passed through exactly.** Signet treats it as
 * opaque. A ticket minted in a system the endpoint's patients are not identified
 * in therefore produces no match rather than a match on the value alone, and the
 * FHIR server is the one that decides.
 *
 * **The search authenticates with a token this endpoint issued.** Every server
 * Signet fronts is a secured one, and an unauthenticated search would work
 * against none of them. Rather than a side-door credential in a second store,
 * Signet signs a short-lived token for itself with the endpoint's own key, scoped
 * to reading patients and passed through the endpoint's own policy - so a
 * resource server that reads an `authorities` claim gets one, exactly as it does
 * for every other token this endpoint issues. If the endpoint's policy will not
 * grant a system read, the resolution fails and says so, which is the honest
 * answer: the endpoint has not been configured to let its authorization server
 * look a patient up.
 *
 * **The search goes through the outbound guard.** The audience is administrator
 * supplied, and a second path to the network would be a second SSRF surface.
 *
 * Author: John Grimes
 */

import {
  assembleAccessTokenClaims,
  evaluatePolicy,
  parseScopes,
} from "@signet/core";
import { getEffectivePolicy, withTenantScope } from "@signet/db";

import { buildEvaluationContext } from "./evaluationContext.js";
import { loadSigningKey, signClaims } from "../keys/signing.js";
import { fetchGuardedJson } from "../security/outboundFetch.js";

import type { ServerContext, ResolvedIssuerContext } from "../context.js";
import type { EvaluationClient, TicketSubject } from "@signet/core";
import type { ClientScope } from "@signet/db";

/**
 * How long the token that authenticates the search is good for, in seconds.
 *
 * It exists for one request. A minute is longer than the request takes and short
 * enough that a copy taken from a proxy log is useless by the time anybody reads
 * it.
 */
export const SUBJECT_RESOLUTION_TOKEN_TTL_SECONDS = 60;

/**
 * The scope the search token asks for.
 *
 * System context, because there is no user: Signet is reading the FHIR server as
 * itself in order to answer a question about a ticket. Read and search only - the
 * narrowest scope that can perform the one query this module makes.
 */
export const SUBJECT_RESOLUTION_SCOPE = "system/Patient.rs";

/** Why a subject could not be resolved to exactly one patient. */
export type SubjectResolutionRefusal =
  /** The search could not be made, or the server refused it. */
  | "search-failed"
  /** The server answered with something that is not a search bundle. */
  | "not-a-bundle"
  /** No patient carries the identifier. */
  | "subject-unknown"
  /** More than one does. */
  | "subject-ambiguous"
  /** The endpoint's policy grants no system read, so no search could be made. */
  | "no-resolution-token";

/** The outcome of resolving a ticket's subject. */
export type SubjectResolutionResult =
  | { readonly ok: true; readonly patientId: string }
  | {
      readonly ok: false;
      readonly reason: SubjectResolutionRefusal;
      readonly description: string;
    };

/** What one patient search is about. */
export interface PatientSearch {
  /** The endpoint's FHIR base URL, which is the token's audience. */
  readonly fhirBaseUrl: string;
  /** The credential to present, as a bearer token. */
  readonly accessToken: string;
  /** The identifier the ticket named its subject by. */
  readonly subject: TicketSubject;
  /** Permits loopback and private addresses. Development and test stacks only. */
  readonly allowPrivateAddresses?: boolean;
}

/** Builds a refusal. */
function refuse(
  reason: SubjectResolutionRefusal,
  description: string,
): SubjectResolutionResult {
  return { ok: false, reason, description };
}

/** The resource ids of the Patients a search bundle returned. */
function patientIdsIn(bundle: Record<string, unknown>): readonly string[] {
  const entries = bundle["entry"];
  if (!Array.isArray(entries)) {
    return [];
  }
  const ids: string[] = [];
  for (const entry of entries as readonly unknown[]) {
    if (typeof entry !== "object" || entry === null) {
      continue;
    }
    const resource = (entry as Record<string, unknown>)["resource"];
    if (typeof resource !== "object" || resource === null) {
      continue;
    }
    const typed = resource as Record<string, unknown>;
    // A search bundle may carry an OperationOutcome describing the search
    // itself. Counting it would turn one match into two and refuse a subject
    // that resolved perfectly well.
    if (typed["resourceType"] !== "Patient") {
      continue;
    }
    const id = typed["id"];
    if (typeof id === "string" && id.length > 0) {
      ids.push(id);
    }
  }
  return ids;
}

/**
 * Searches a FHIR server for the one patient carrying an identifier.
 *
 * @param search - The audience, the credential, and the identifier to find.
 * @returns The resource id of the single matching patient, or why the search
 *   produced no usable answer. Never throws for a network or content failure:
 *   each is a refusal the caller has to audit.
 * @example
 * ```ts
 * const found = await searchPatientByIdentifier({
 *   fhirBaseUrl: endpoint.fhirBaseUrl,
 *   accessToken,
 *   subject: ticket.subject,
 *   allowPrivateAddresses: config.allowPrivateOutboundFetches,
 * });
 * ```
 */
export async function searchPatientByIdentifier(
  search: PatientSearch,
): Promise<SubjectResolutionResult> {
  const base = search.fhirBaseUrl.replace(/\/+$/u, "");
  const parameters = new URLSearchParams({
    identifier: `${search.subject.system}|${search.subject.value}`,
    // Enough to see a duplicate, and no more. A server whose default page size
    // is one would otherwise answer a two-patient duplicate with a single entry,
    // which counting entries alone reads as a clean match.
    _count: "2",
  });
  const url = `${base}/Patient?${parameters.toString()}`;

  const fetched = await fetchGuardedJson(url, {
    allowPrivateAddresses: search.allowPrivateAddresses ?? false,
    headers: { authorization: `Bearer ${search.accessToken}` },
  });
  if (!fetched.ok) {
    // Never a fallback. A server that would not answer has not said the subject
    // is unknown; it has said nothing.
    return refuse(
      "search-failed",
      `The subject could not be resolved: ${fetched.description}`,
    );
  }

  const body = fetched.value;
  if (
    typeof body !== "object" ||
    body === null ||
    Array.isArray(body) ||
    (body as Record<string, unknown>)["resourceType"] !== "Bundle"
  ) {
    return refuse(
      "not-a-bundle",
      `${base} did not answer the patient search with a Bundle`,
    );
  }

  const ids = patientIdsIn(body as Record<string, unknown>);
  const only = ids[0];
  if (only === undefined) {
    return refuse(
      "subject-unknown",
      "The permission ticket's subject is unknown to this endpoint's FHIR server",
    );
  }
  // `total` and the entry count are each authoritative about a duplicate the
  // other can miss: a server that paginated the second match away reports it
  // only in `total`, and one that omits `total` reports it only in the entries.
  // Whichever says "more than one" is the answer, because the only safe reading
  // of a duplicate is a refusal.
  const reported = (body as Record<string, unknown>)["total"];
  const matches =
    typeof reported === "number" && Number.isInteger(reported)
      ? Math.max(reported, ids.length)
      : ids.length;
  if (matches > 1) {
    return refuse(
      "subject-ambiguous",
      `The permission ticket's subject is ambiguous: ${String(matches)} patients carry that identifier`,
    );
  }
  return { ok: true, patientId: only };
}

/** What a resolution needs beyond the ticket's subject. */
export interface SubjectResolutionRequest {
  readonly issuerContext: ResolvedIssuerContext;
  /** The presenting client, whose effective policy governs the search token. */
  readonly clientScope: ClientScope;
  readonly client: EvaluationClient;
  readonly subject: TicketSubject;
}

/**
 * Signs the short-lived token the search is made with.
 *
 * Through the endpoint's own policy and its own key, so the resource server sees
 * a token indistinguishable in kind from every other one this endpoint issues.
 * Nothing is recorded: this token is never introspected, never revoked and never
 * refreshed, and an `access_tokens` row for it would show in the console as a
 * credential somebody holds.
 */
async function issueResolutionToken(
  context: ServerContext,
  request: SubjectResolutionRequest,
): Promise<
  | { readonly ok: true; readonly accessToken: string }
  | { readonly ok: false; readonly description: string }
> {
  const { issuerContext } = request;
  const policy = await withTenantScope(
    context.db,
    request.clientScope,
    (bound) => getEffectivePolicy(bound),
  );
  if (policy === undefined) {
    return {
      ok: false,
      description: "this endpoint has no published policy",
    };
  }

  const evaluationContext = buildEvaluationContext({
    issuerContext,
    client: request.client,
    user: null,
    requested: parseScopes(SUBJECT_RESOLUTION_SCOPE).scopes,
    launchContext: {},
    // The token acts as the endpoint rather than for a user, which is what a
    // client credentials grant is. Evaluating it as anything else would ask the
    // policy a question about a user that does not exist.
    grantType: "client_credentials",
  });

  const evaluated = evaluatePolicy(policy.document, evaluationContext);
  if (evaluated.grantedScopes.length === 0) {
    return {
      ok: false,
      description: `this endpoint's policy grants no ${SUBJECT_RESOLUTION_SCOPE}, so no subject can be looked up`,
    };
  }

  const load = await loadSigningKey(
    context.db,
    request.clientScope,
    context.config.masterKey,
  );
  if (!load.ok) {
    return {
      ok: false,
      description: "this endpoint has no active signing key",
    };
  }

  const issuedAt = Math.floor(context.clock().getTime() / 1000);
  const claims = assembleAccessTokenClaims({
    evaluation: {
      ...evaluated,
      accessTokenTtl: SUBJECT_RESOLUTION_TOKEN_TTL_SECONDS,
    },
    context: evaluationContext,
    issuance: {
      jti: crypto.randomUUID(),
      issuedAt,
      // The endpoint itself. There is no user and no client acting for one: this
      // is the authorization server reading the server it fronts.
      subject: issuerContext.issuer,
    },
  });

  return { ok: true, accessToken: await signClaims(claims, load.signingKey) };
}

/**
 * Resolves a ticket's subject identifier to exactly one patient.
 *
 * @param context - The server's dependencies.
 * @param request - The endpoint, the presenting client, and the ticket's subject.
 * @returns The resource id of the single matching patient, or why the exchange
 *   must be refused.
 * @example
 * ```ts
 * const resolved = await resolveTicketSubject(context, {
 *   issuerContext,
 *   clientScope: authenticated.scope,
 *   client: toEvaluationClient(authenticated.client),
 *   subject: ticket.subject,
 * });
 * ```
 */
export async function resolveTicketSubject(
  context: ServerContext,
  request: SubjectResolutionRequest,
): Promise<SubjectResolutionResult> {
  const token = await issueResolutionToken(context, request);
  if (!token.ok) {
    return refuse(
      "no-resolution-token",
      `The subject could not be resolved: ${token.description}`,
    );
  }

  return await searchPatientByIdentifier({
    fhirBaseUrl: request.issuerContext.endpoint.fhirBaseUrl,
    accessToken: token.accessToken,
    subject: request.subject,
    allowPrivateAddresses: context.config.allowPrivateOutboundFetches,
  });
}
