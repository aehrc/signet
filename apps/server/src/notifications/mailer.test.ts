/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The SMTP transport, against a real SMTP server on loopback.
 *
 * Author: John Grimes
 */

import { afterEach, describe, expect, it } from "bun:test";

import { createSmtpMailer } from "./mailer.js";
import { startSmtpSink } from "../test/smtpSink.js";

import type { SmtpConfig } from "../config.js";
import type { SmtpSink, SmtpSinkOptions } from "../test/smtpSink.js";

const EMAIL = {
  to: "owner@example.org",
  subject: "New client registration request for Clinical FHIR (Demo)",
  text: "App name: Growth Charts\n\nhttps://signet.example.org/console",
};

let sink: SmtpSink | undefined;

afterEach(async () => {
  await sink?.close();
  sink = undefined;
});

/** Starts a sink and a mailer pointed at it. */
async function mailerFor(
  overrides: Partial<SmtpConfig> = {},
  sinkOptions: SmtpSinkOptions = {},
) {
  sink = await startSmtpSink(sinkOptions);
  const config: SmtpConfig = {
    host: "127.0.0.1",
    port: sink.port,
    tls: "optional",
    credentials: undefined,
    from: "Signet <signet@example.org>",
    ...overrides,
  };
  return { sink, send: createSmtpMailer(config) };
}

describe("createSmtpMailer", () => {
  it("delivers a plain-text message from the configured sender", async () => {
    const { sink, send } = await mailerFor();

    await send(EMAIL);

    const [message] = await sink.waitForMessages(1);
    expect(message?.from).toBe("signet@example.org");
    expect(message?.to).toEqual(["owner@example.org"]);
    expect(message?.headers["subject"]).toBe(EMAIL.subject);
    expect(message?.headers["content-type"]).toStartWith("text/plain");
    // Replying goes to the deployment's own address, never to whoever filed the
    // request: that address is whatever an anonymous submitter typed.
    expect(message?.headers["reply-to"]).toBeUndefined();
    expect(message?.text).toBe(EMAIL.text);
  });

  it("presents the configured credentials", async () => {
    const credentials = { username: "AKIAEXAMPLE", password: "smtp-secret" };
    const { sink, send } = await mailerFor({ credentials }, { credentials });

    await send(EMAIL);

    expect(await sink.waitForMessages(1)).toHaveLength(1);
  });

  it("fails when the relay refuses the credentials", async () => {
    const { sink, send } = await mailerFor(
      { credentials: { username: "AKIAEXAMPLE", password: "wrong" } },
      { credentials: { username: "AKIAEXAMPLE", password: "smtp-secret" } },
    );

    // Awaited, so the conversation is over: nothing can still be arriving.
    await expect(send(EMAIL)).rejects.toThrow();
    expect(sink.messages).toHaveLength(0);
  });

  it("fails when the relay refuses the recipient", async () => {
    const { sink, send } = await mailerFor(
      {},
      { rejectRecipients: ["owner@example.org"] },
    );

    // Awaited, so the conversation is over: nothing can still be arriving.
    await expect(send(EMAIL)).rejects.toThrow();
    expect(sink.messages).toHaveLength(0);
  });

  // The sink offers no TLS. A transport that required it and quietly carried on
  // in the clear would hand an SMTP password to anybody on the path.
  it("will not send in plaintext when STARTTLS is required", async () => {
    const { sink, send } = await mailerFor({ tls: "starttls" });

    // Awaited, so the conversation is over: nothing can still be arriving.
    await expect(send(EMAIL)).rejects.toThrow();
    expect(sink.messages).toHaveLength(0);
  });

  it("will not fall back to plaintext when implicit TLS is configured", async () => {
    const { sink, send } = await mailerFor({ tls: "implicit" });

    // Awaited, so the conversation is over: nothing can still be arriving.
    await expect(send(EMAIL)).rejects.toThrow();
    expect(sink.messages).toHaveLength(0);
  });
});
