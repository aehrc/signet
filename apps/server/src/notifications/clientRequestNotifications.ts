/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Telling an endpoint's reviewers that a registration request has been filed.
 *
 * Best effort, and never on the submission's critical path. The portal handler
 * starts this and answers the developer without waiting, so a relay that is slow,
 * refusing or unreachable changes what the audit trail says and nothing the
 * developer sees. There is no retry and no queue: a notification is a prompt to
 * open the console, and the request itself is already safely stored and listed
 * there whether or not the prompt arrives.
 *
 * What does have to be visible is a prompt that did not arrive, so every round
 * ends in exactly one audit event - `client-request.notified` when every reviewer
 * was reached, `client-request.notification-failed` otherwise. The event carries
 * counts and error codes and no addresses: who administers a tenant is not
 * something the trail needs to repeat, and the members list already says it.
 *
 * Each reviewer is sent a message of their own, one after another. Separate
 * messages keep one reviewer's address out of another's headers; sequential sends
 * keep a tenant with many administrators from opening that many connections to
 * the relay at once.
 *
 * Author: John Grimes
 */

import {
  composeClientRequestNotification,
  summariseNotification,
} from "@signet/core";
import { listRequestReviewers, withTenantScope } from "@signet/db";

import { logRecord } from "../observability/log.js";

import type { ServerContext } from "../context.js";
import type {
  ClientRequest,
  Endpoint,
  EndpointScope,
  Tenant,
} from "@signet/db";

/** A request that has just been filed, and where. */
export interface FiledClientRequest {
  readonly tenant: Tenant;
  readonly endpoint: Endpoint;
  readonly scope: EndpointScope;
  readonly request: ClientRequest;
}

/**
 * The code a failed send is recorded under.
 *
 * Nodemailer tags its errors (`EAUTH`, `EENVELOPE`, `ETIMEDOUT` and so on), and
 * the tag is what an operator can act on without the message, which may quote
 * the relay's reply and with it a recipient's address.
 */
function errorCode(error: unknown): string {
  if (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    typeof error.code === "string"
  ) {
    return error.code;
  }
  return "unknown";
}

/**
 * Emails every reviewer of the request's tenant, and records how that went.
 *
 * Does nothing when no relay is configured. Never rejects: a failure is logged
 * and recorded rather than thrown, because the caller has already answered the
 * request and has nobody to hand an error to.
 *
 * @param context - The server's dependencies; `mailer` is what sends.
 * @param filed - The request, as just stored, and the endpoint it was filed on.
 * @returns Once the round has finished and its outcome has been recorded.
 * @example
 * ```ts
 * // Deliberately not awaited: the submission does not wait on the relay.
 * void notifyClientRequestReviewers(context, { tenant, endpoint, scope, request });
 * ```
 */
export async function notifyClientRequestReviewers(
  context: ServerContext,
  filed: FiledClientRequest,
): Promise<void> {
  const { mailer } = context;
  if (mailer === undefined) {
    return;
  }
  const { tenant, endpoint, scope, request } = filed;
  const where = {
    tenantId: tenant.id,
    endpointSlug: endpoint.slug,
    requestId: request.id,
  };

  try {
    const reviewers = await withTenantScope(context.db, scope, (bound) =>
      listRequestReviewers(bound),
    );
    const email = composeClientRequestNotification({
      publicUrl: context.config.publicUrl,
      tenant,
      endpoint,
      request: request.payload,
    });

    const failures: string[] = [];
    for (const reviewer of reviewers) {
      try {
        await mailer({ to: reviewer.email, ...email });
      } catch (error) {
        const code = errorCode(error);
        failures.push(code);
        // The message goes to the operator's log and not the audit trail: it is
        // the relay's own reply, which is what diagnoses the fault.
        logRecord(
          context.config.logLevel,
          "warn",
          "signet.notification.send-failed",
          {
            ...where,
            code,
            error: error instanceof Error ? error.message : String(error),
          },
        );
      }
    }

    const outcome = summariseNotification(reviewers.length, failures);
    if (!outcome.ok && outcome.reason === "no-recipients") {
      // Logged as well as audited, so an operator alerting on the log learns that
      // a request arrived with nobody able to decide it.
      logRecord(
        context.config.logLevel,
        "warn",
        "signet.notification.no-recipients",
        where,
      );
    }
    const { ok, ...detail } = outcome;
    await context.audit.record(context.db, {
      tenantId: tenant.id,
      endpointId: endpoint.id,
      endpointSlug: endpoint.slug,
      actor: { type: "system" },
      action: ok
        ? "client-request.notified"
        : "client-request.notification-failed",
      target: { type: "client-request", id: request.id },
      detail,
    });
  } catch (error) {
    // Reading the reviewers or writing the outcome failed - the database, most
    // likely. There is no audit row to be had, so the log is the only record.
    logRecord(context.config.logLevel, "error", "signet.notification.failed", {
      ...where,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}
