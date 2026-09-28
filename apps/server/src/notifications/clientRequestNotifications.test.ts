/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The notifier's refusal to throw, which nothing with a working database reaches.
 *
 * The portal handler starts a notification and does not await it, so a rejection
 * would be unhandled - and an unhandled rejection ends a Node process. The
 * database being unreachable is the likeliest way to get one.
 *
 * Author: John Grimes
 */

import { describe, expect, it, mock, spyOn } from "bun:test";

import { notifyClientRequestReviewers } from "./clientRequestNotifications.js";

import type { FiledClientRequest } from "./clientRequestNotifications.js";
import type { ServerContext } from "../context.js";

/** A context whose database refuses every transaction. */
function unreachableDatabase(
  mailer: ServerContext["mailer"],
  record: ServerContext["audit"]["record"],
): ServerContext {
  return {
    config: { logLevel: "error", publicUrl: "https://signet.example.org" },
    db: {
      transaction: () => Promise.reject(new Error("connection refused")),
    },
    audit: { record },
    mailer,
  } as unknown as ServerContext;
}

const FILED = {
  tenant: { id: "tenant-1", slug: "demo", name: "Demo" },
  endpoint: { id: "endpoint-1", slug: "fhir", name: "FHIR" },
  scope: {},
  request: { id: "request-1", payload: {} },
} as unknown as FiledClientRequest;

describe("notifyClientRequestReviewers", () => {
  it("resolves and logs rather than rejecting when the database is down", async () => {
    const mailer = mock(() => Promise.resolve());
    const record = mock(() => Promise.resolve());
    const written: string[] = [];
    const error = spyOn(console, "error").mockImplementation((line: string) => {
      written.push(line);
    });

    try {
      await notifyClientRequestReviewers(
        unreachableDatabase(mailer, record),
        FILED,
      );
    } finally {
      error.mockRestore();
    }

    expect(mailer).not.toHaveBeenCalled();
    expect(record).not.toHaveBeenCalled();
    expect(written.map((line) => JSON.parse(line) as unknown)).toEqual([
      {
        level: "error",
        message: "signet.notification.failed",
        tenantId: "tenant-1",
        endpointSlug: "fhir",
        requestId: "request-1",
        error: "connection refused",
      },
    ]);
  });
});
