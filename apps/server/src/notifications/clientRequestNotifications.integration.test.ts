/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Telling an endpoint's reviewers that a registration request has arrived.
 *
 * Driven end to end: a request is filed through the public portal route of the real
 * app, over a real database, and the mail is read back off a real SMTP server. The
 * suite's spine is that the submission never depends on the mail - a relay that is
 * slow, refusing or absent changes what the audit trail says and nothing else.
 *
 * Author: John Grimes
 */

import {
  createAdminUser,
  deleteAdminUser,
  queryAuditEvents,
  setAdminUserDisabled,
  setTenantMemberRole,
  withTenantScope,
} from "@signet/db";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "bun:test";

import { createSmtpMailer } from "./mailer.js";
import { issuerPath } from "../test/flows.js";
import {
  createTestStack,
  TEST_PUBLIC_URL,
  testDatabaseUrl,
} from "../test/harness.js";
import { startSmtpSink } from "../test/smtpSink.js";

import type { Mailer } from "./mailer.js";
import type { TestStack } from "../test/harness.js";
import type { SmtpSink, SmtpSinkOptions } from "../test/smtpSink.js";
import type { AdminUser, AuditAction, TenantRole } from "@signet/db";

const describeWithDatabase =
  testDatabaseUrl === undefined ? describe.skip : describe;

const SUBMISSION = {
  name: "Growth Chart",
  contactEmail: "dev@example.org",
  clientType: "public",
  redirectUris: ["https://growth.test/cb"],
  requestedScopes: ["openid", "patient/Observation.rs"],
  note: "Plots a child's growth against reference curves.",
};

/** A mailer that talks to the sink in the clear, which is all it offers. */
function mailerFor(port: number): Mailer {
  return createSmtpMailer({
    host: "127.0.0.1",
    port,
    tls: "optional",
    credentials: undefined,
    from: "Signet <signet@signet.test>",
  });
}

describeWithDatabase("registration request notifications", () => {
  let sink: SmtpSink;
  let stack: TestStack;
  /** Console identities this suite created, deleted when it finishes. */
  const created: AdminUser[] = [];

  /** Creates a console identity holding `role` in the stack's tenant. */
  async function member(target: TestStack, role: TenantRole, email?: string) {
    const user = await createAdminUser(target.context.db, {
      email:
        email ??
        `${role}-${String(created.length)}-${target.tenant.slug}@signet.test`,
      passwordHash: "$argon2id$placeholder",
      displayName: `A ${role}`,
    });
    created.push(user);
    const granted = await withTenantScope(
      target.context.db,
      target.tenantScope,
      (bound) => setTenantMemberRole(bound, user.id, role),
    );
    expect(granted.ok).toBe(true);
    return user;
  }

  /** Files a request through the portal and returns its identifier. */
  async function submit(target: TestStack = stack): Promise<string> {
    const response = await target.app.request(
      `${issuerPath(target)}/apps/requests`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(SUBMISSION),
      },
    );
    expect(response.status).toBe(201);
    const body = (await response.json()) as { request: { id: string } };
    return body.request.id;
  }

  /**
   * Waits for the notification outcome of one request to reach the audit trail.
   *
   * The outcome is written after the submission has been answered, so the suite
   * waits on the row itself rather than on a guessed delay.
   */
  async function outcomeOf(target: TestStack, requestId: string) {
    const actions: AuditAction[] = [
      "client-request.notified",
      "client-request.notification-failed",
    ];
    const deadline = Date.now() + 5000;
    for (;;) {
      const page = await withTenantScope(
        target.context.db,
        target.tenantScope,
        (bound) => queryAuditEvents(bound, { actions, limit: 50 }),
      );
      const event = page.events.find(
        (candidate) => candidate.targetId === requestId,
      );
      if (event !== undefined) {
        return event;
      }
      if (Date.now() > deadline) {
        throw new Error(`no notification outcome for ${requestId}`);
      }
      // Polling the database, which has no way to announce a row. Bounded by the
      // deadline above; a passing test exits on its first or second read.
      await Bun.sleep(20);
    }
  }

  /** Builds a second stack for a case that needs a sink or roster of its own. */
  async function isolatedStack(
    sinkOptions: SmtpSinkOptions = {},
  ): Promise<{ stack: TestStack; sink: SmtpSink }> {
    const ownSink = await startSmtpSink(sinkOptions);
    const own = await createTestStack({
      endpoint: { supportsDynamicRegistration: true },
      mailer: mailerFor(ownSink.port),
    });
    return { stack: own, sink: ownSink };
  }

  let admin: AdminUser;

  beforeAll(async () => {
    sink = await startSmtpSink();
    stack = await createTestStack({
      endpoint: { supportsDynamicRegistration: true },
      mailer: mailerFor(sink.port),
    });
    admin = await member(stack, "admin");
    await member(stack, "developer");
    await member(stack, "viewer");
    const disabled = await member(stack, "admin");
    await setAdminUserDisabled(stack.context.db, disabled.id, true);
  });

  afterEach(() => {
    sink.clear();
  });

  afterAll(async () => {
    // Before the stack closes, because closing it releases the connection.
    for (const user of created) {
      await deleteAdminUser(stack.context.db, user.id);
    }
    await stack.close();
    await sink.close();
  });

  it("mails each owner and admin, and nobody else", async () => {
    const requestId = await submit();

    const messages = await sink.waitForMessages(2);
    // One message per reviewer, so no reviewer learns who else administers the
    // tenant from the headers.
    expect(messages.map((message) => message.to).toSorted()).toEqual(
      [[stack.admin.email], [admin.email]].toSorted(),
    );
    const event = await outcomeOf(stack, requestId);
    expect(event.action).toBe("client-request.notified");
    expect(sink.messages).toHaveLength(2);
  });

  it("says what was asked for and where to decide it", async () => {
    const requestId = await submit();
    // Waited for so the round is over before the next test clears the sink.
    await outcomeOf(stack, requestId);

    const [message] = await sink.waitForMessages(1);
    expect(message?.from).toBe("signet@signet.test");
    expect(message?.headers["subject"]).toBe(
      `New client registration request for ${stack.endpoint.name} (${stack.tenant.name})`,
    );
    expect(message?.text).toContain("App name: Growth Chart");
    expect(message?.text).toContain("Contact email: dev@example.org");
    expect(message?.text).toContain("  patient/Observation.rs");
    expect(message?.text).toContain(
      `${TEST_PUBLIC_URL}/console/t/${stack.tenant.slug}/e/${stack.endpoint.slug}/requests`,
    );
  });

  it("records the delivery, without the addresses it went to", async () => {
    const requestId = await submit();

    const event = await outcomeOf(stack, requestId);
    expect(event.action).toBe("client-request.notified");
    expect(event.actorType).toBe("system");
    expect(event.endpointId).toBe(stack.endpoint.id);
    expect(event.detail).toMatchObject({ recipients: 2 });
    expect(JSON.stringify(event)).not.toContain(admin.email);
  });

  it("answers the submission without waiting on the relay", async () => {
    const release = sink.hold();
    try {
      // The relay is holding every message open, so a handler that awaited the
      // mail would not answer until it was released.
      const requestId = await submit();
      expect(sink.messages).toHaveLength(0);

      release();
      await sink.waitForMessages(2);
      expect((await outcomeOf(stack, requestId)).action).toBe(
        "client-request.notified",
      );
    } finally {
      release();
    }
  });

  it("records a refused recipient as a failure, and still delivers to the rest", async () => {
    const refusedEmail = `refused-${String(process.pid)}@signet.test`;
    const own = await isolatedStack({ rejectRecipients: [refusedEmail] });
    try {
      await member(own.stack, "admin", refusedEmail);

      const requestId = await submit(own.stack);

      const event = await outcomeOf(own.stack, requestId);
      expect(event.action).toBe("client-request.notification-failed");
      expect(event.detail).toMatchObject({
        reason: "delivery-failed",
        recipients: 2,
        delivered: 1,
      });
      expect(JSON.stringify(event.detail)).not.toContain(refusedEmail);
      // The owner was still told: one bad address does not silence the others.
      expect(own.sink.messages.map((message) => message.to)).toEqual([
        [own.stack.admin.email],
      ]);
    } finally {
      await own.stack.close();
      await own.sink.close();
    }
  });

  it("records an unreachable relay as a failure and still files the request", async () => {
    const own = await isolatedStack();
    try {
      await own.sink.close();

      const requestId = await submit(own.stack);

      const event = await outcomeOf(own.stack, requestId);
      expect(event.action).toBe("client-request.notification-failed");
      expect(event.detail).toMatchObject({
        reason: "delivery-failed",
        recipients: 1,
        delivered: 0,
      });
    } finally {
      await own.stack.close();
    }
  });

  it("records that nobody could be told when no reviewer is active", async () => {
    const own = await isolatedStack();
    try {
      // The tenant's only owner is locked out, and nobody else may decide.
      await setAdminUserDisabled(
        own.stack.context.db,
        own.stack.admin.id,
        true,
      );

      const requestId = await submit(own.stack);

      const event = await outcomeOf(own.stack, requestId);
      expect(event.action).toBe("client-request.notification-failed");
      expect(event.detail).toMatchObject({
        reason: "no-recipients",
        recipients: 0,
        delivered: 0,
      });
      expect(own.sink.messages).toHaveLength(0);
    } finally {
      await own.stack.close();
      await own.sink.close();
    }
  });

  it("sends nothing and records nothing when no relay is configured", async () => {
    const own = await createTestStack({
      endpoint: { supportsDynamicRegistration: true },
    });
    try {
      const requestId = await submit(own);

      // The submission's own event is written before the response, so once it is
      // readable any notification outcome would have had its chance to start; the
      // assertion is that the notifier never ran at all.
      const page = await withTenantScope(
        own.context.db,
        own.tenantScope,
        (bound) =>
          queryAuditEvents(bound, {
            actions: [
              "client-request.submitted",
              "client-request.notified",
              "client-request.notification-failed",
            ],
            limit: 50,
          }),
      );
      expect(
        page.events
          .filter((event) => event.targetId === requestId)
          .map((event) => event.action),
      ).toEqual(["client-request.submitted"]);
    } finally {
      await own.close();
    }
  });
});
