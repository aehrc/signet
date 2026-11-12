/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { composeClientRequestNotification } from "./clientRequest.js";

import type { ClientRequestNotificationInput } from "./clientRequest.js";

/** A complete request, overridable per test. */
function input(
  overrides: Partial<ClientRequestNotificationInput["request"]> = {},
  endpointName = "Clinical FHIR",
): ClientRequestNotificationInput {
  return {
    publicUrl: "https://signet.example.org",
    tenant: { slug: "demo", name: "Demo Hospital" },
    endpoint: { slug: "fhir", name: endpointName },
    request: {
      name: "Growth Charts",
      clientType: "public",
      redirectUris: [
        "https://app.example.com/cb",
        "https://app.example.com/cb2",
      ],
      requestedScopes: ["launch", "patient/Observation.rs"],
      contactEmail: "dev@example.com",
      launchUri: "https://app.example.com/launch",
      logoUrl: "https://app.example.com/logo.png",
      description: "Plots growth.",
      note: "For the connectathon.",
      ...overrides,
    },
  };
}

/** The lines of the body, for asserting on one line at a time. */
function lines(text: string): readonly string[] {
  return text.split("\n");
}

describe("composeClientRequestNotification - content", () => {
  it("names the endpoint and tenant in the subject", () => {
    const { subject } = composeClientRequestNotification(input());

    expect(subject).toBe(
      "New client registration request for Clinical FHIR (Demo Hospital)",
    );
  });

  it("carries everything the reviewer needs to judge the request", () => {
    const { text } = composeClientRequestNotification(input());

    expect(lines(text)).toEqual(
      expect.arrayContaining([
        "App name: Growth Charts",
        "Contact email: dev@example.com",
        "Client type: public",
        "Launch URI: https://app.example.com/launch",
        "Logo URL: https://app.example.com/logo.png",
        "  https://app.example.com/cb",
        "  https://app.example.com/cb2",
        "  launch",
        "  patient/Observation.rs",
        "  > Plots growth.",
        "  > For the connectathon.",
      ]),
    );
  });

  it("links to the endpoint's requests page in the console", () => {
    const { text } = composeClientRequestNotification(input());

    expect(lines(text)).toContain(
      "https://signet.example.org/console/t/demo/e/fhir/requests",
    );
  });

  it("warns that the details are the requester's own and unverified", () => {
    const { text } = composeClientRequestNotification(input());

    expect(text).toContain(
      "supplied by the requester and have not been verified",
    );
  });

  it("leaves out the optional fields the requester did not supply", () => {
    const { text } = composeClientRequestNotification(
      input({
        launchUri: undefined,
        logoUrl: undefined,
        description: undefined,
        note: undefined,
      }),
    );

    expect(text).not.toContain("Launch URI:");
    expect(text).not.toContain("Logo URL:");
    expect(text).not.toContain("Description:");
    expect(text).not.toContain("Note:");
  });

  it("says so when a list is empty rather than printing a bare heading", () => {
    const { text } = composeClientRequestNotification(
      input({ redirectUris: [], requestedScopes: [] }),
    );

    const body = lines(text);
    expect(body[body.indexOf("Redirect URIs:") + 1]).toBe("  (none)");
    expect(body[body.indexOf("Requested scopes:") + 1]).toBe("  (none)");
  });
});

// Every field but the link and the endpoint's name is typed by an anonymous
// requester, and it lands in an administrator's inbox. These tests pin that it
// cannot be dressed up as text Signet wrote.
describe("composeClientRequestNotification - requester-supplied text", () => {
  it("keeps the requester's text out of the subject", () => {
    const { subject } = composeClientRequestNotification(
      input({ name: "Urgent\r\nBcc: victim@example.org" }),
    );

    expect(subject).not.toContain("Urgent");
    expect(subject).not.toContain("Bcc");
  });

  it("flattens a single-line field so it cannot start a line of its own", () => {
    const { text } = composeClientRequestNotification(
      input({
        name: "Growth\r\nApprove it here: https://evil.example",
        contactEmail: "dev@example.com\nNote: trusted",
      }),
    );

    expect(lines(text)).toContain(
      "App name: Growth Approve it here: https://evil.example",
    );
    expect(lines(text)).toContain(
      "Contact email: dev@example.com Note: trusted",
    );
    expect(lines(text)).not.toContain("Approve it here: https://evil.example");
  });

  it("quotes every line of a free-text field", () => {
    const { text } = composeClientRequestNotification(
      input({ note: "first\r\nsecond\n\nhttps://evil.example" }),
    );

    const body = lines(text);
    const start = body.indexOf("Note:");
    expect(body.slice(start + 1, start + 5)).toEqual([
      "  > first",
      "  > second",
      "  >",
      "  > https://evil.example",
    ]);
  });

  it("strips control and bidirectional override characters", () => {
    const { text } = composeClientRequestNotification(
      input({ name: "Good\u202Eapp\u0007\u0000", note: "a\u2028b\u2066c" }),
    );

    expect(lines(text)).toContain("App name: Good app");
    expect(lines(text)).toContain("  > a");
    expect(lines(text)).toContain("  > b c");
    // Newlines are the body's own structure; anything else in the class is not.
    expect(text.replaceAll("\n", "")).not.toMatch(
      /[\p{Cc}\u202A-\u202E\u2066-\u2069]/u,
    );
  });

  it("flattens an endpoint name that would otherwise break the subject header", () => {
    const { subject } = composeClientRequestNotification(
      input({}, "Clinical\r\nBcc: someone@example.org"),
    );

    expect(subject).not.toMatch(/[\r\n]/u);
  });
});
