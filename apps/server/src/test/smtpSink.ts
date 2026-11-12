/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * A real SMTP server on loopback, for the suites that send mail.
 *
 * Real rather than a stub mailer function, because the properties worth asserting
 * are properties of the conversation: that a transport configured to require
 * STARTTLS will not fall back to plaintext, that credentials are presented, that a
 * rejected recipient is reported as a failure rather than swallowed. A function
 * standing in for the transport would pass all of those whatever the transport did.
 *
 * Author: John Grimes
 */

import { SMTPServer } from "smtp-server";

import type { AddressInfo } from "node:net";

/** One message as the sink received it. */
export interface ReceivedMessage {
  readonly from: string;
  readonly to: readonly string[];
  /** The message's headers, names lower-cased. */
  readonly headers: Readonly<Record<string, string>>;
  /** The body, with its transfer encoding undone. */
  readonly text: string;
}

/** How the sink should behave. */
export interface SmtpSinkOptions {
  /** Requires `AUTH` with exactly these credentials. */
  readonly credentials?: {
    readonly username: string;
    readonly password: string;
  };
  /** Recipients refused at `RCPT TO` with a permanent failure. */
  readonly rejectRecipients?: readonly string[];
}

/** A running sink. */
export interface SmtpSink {
  readonly port: number;
  /** Every message accepted so far, in the order the data finished arriving. */
  readonly messages: readonly ReceivedMessage[];
  /**
   * Stops completing `DATA` until the returned function is called.
   *
   * The message has been sent by then and the client is waiting on the final
   * reply, which is the state a slow relay leaves a transport in.
   */
  readonly hold: () => () => void;
  /** Resolves once at least `count` messages have arrived. */
  readonly waitForMessages: (
    count: number,
    timeoutMs?: number,
  ) => Promise<readonly ReceivedMessage[]>;
  /** Forgets every message received so far, between tests sharing a sink. */
  readonly clear: () => void;
  readonly close: () => Promise<void>;
}

/** Undoes quoted-printable encoding, the one nodemailer uses for long lines. */
function decodeQuotedPrintable(body: string): string {
  const bytes = body
    .replaceAll(/=\r?\n/gu, "")
    .replaceAll(/=([0-9A-F]{2})/gu, (_, hex: string) =>
      String.fromCodePoint(Number.parseInt(hex, 16)),
    );
  return Buffer.from(bytes, "latin1").toString("utf8");
}

/** Splits a raw message into headers and a decoded body. */
function parseMessage(raw: string): Pick<ReceivedMessage, "headers" | "text"> {
  const separator = raw.indexOf("\r\n\r\n");
  const head = raw.slice(0, separator).replaceAll(/\r\n[ \t]+/gu, " ");
  const body = raw.slice(separator + 4);

  const headers: Record<string, string> = {};
  for (const line of head.split("\r\n")) {
    const colon = line.indexOf(":");
    headers[line.slice(0, colon).trim().toLowerCase()] = line
      .slice(colon + 1)
      .trim();
  }

  const encoding = headers["content-transfer-encoding"]?.toLowerCase();
  let decoded = body;
  if (encoding === "quoted-printable") {
    decoded = decodeQuotedPrintable(body);
  } else if (encoding === "base64") {
    decoded = Buffer.from(body, "base64").toString("utf8");
  }
  return { headers, text: decoded.replaceAll("\r\n", "\n").trimEnd() };
}

/**
 * Starts a sink on an ephemeral loopback port.
 *
 * Offers no TLS at all, so a client that insists on it has nothing to upgrade to.
 *
 * @param options - How the sink should behave.
 * @returns The running sink.
 */
export async function startSmtpSink(
  options: SmtpSinkOptions = {},
): Promise<SmtpSink> {
  const messages: ReceivedMessage[] = [];
  const rejected = new Set(options.rejectRecipients);
  let held: Promise<void> = Promise.resolve();
  // Callers of `waitForMessages`, woken as each message lands rather than polling.
  const waiters: { readonly count: number; readonly wake: () => void }[] = [];

  const server = new SMTPServer({
    logger: false,
    disabledCommands:
      options.credentials === undefined ? ["STARTTLS", "AUTH"] : ["STARTTLS"],
    authOptional: options.credentials === undefined,
    // No TLS is on offer, so credentials can only arrive in the clear.
    allowInsecureAuth: true,
    onAuth(auth, _session, callback) {
      const expected = options.credentials;
      if (
        expected !== undefined &&
        auth.username === expected.username &&
        auth.password === expected.password
      ) {
        callback(null, { user: auth.username });
        return;
      }
      callback(new Error("Invalid username or password"));
    },
    onRcptTo(address, _session, callback) {
      if (rejected.has(address.address)) {
        callback(
          Object.assign(new Error("Mailbox unavailable"), {
            responseCode: 550,
          }),
        );
        return;
      }
      callback();
    },
    onData(stream, session, callback) {
      const chunks: Buffer[] = [];
      stream.on("data", (chunk: Buffer) => chunks.push(chunk));
      stream.on("end", () => {
        void held.then(() => {
          const mailFrom = session.envelope.mailFrom;
          messages.push({
            from: mailFrom === false ? "" : mailFrom.address,
            to: session.envelope.rcptTo.map((address) => address.address),
            ...parseMessage(Buffer.concat(chunks).toString("latin1")),
          });
          for (const waiter of waiters.filter(
            (candidate) => messages.length >= candidate.count,
          )) {
            waiter.wake();
          }
          callback();
        });
      });
    },
  });

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
  const { port } = server.server.address() as AddressInfo;

  return {
    port,
    messages,
    hold: () => {
      let release = () => {};
      held = new Promise<void>((resolve) => {
        release = resolve;
      });
      return release;
    },
    waitForMessages: async (count, timeoutMs = 5000) => {
      if (messages.length < count) {
        // The timeout is a deadline for a failing test, not a wait: a passing one
        // is woken by the message itself.
        await new Promise<void>((resolve, reject) => {
          const timer = setTimeout(() => {
            reject(
              new Error(
                `expected ${String(count)} messages, received ${String(messages.length)}`,
              ),
            );
          }, timeoutMs);
          waiters.push({
            count,
            wake: () => {
              clearTimeout(timer);
              resolve();
            },
          });
        });
      }
      return messages;
    },
    clear: () => {
      messages.splice(0);
    },
    close: async () => {
      await new Promise<void>((resolve) => {
        server.close(() => {
          resolve();
        });
      });
    },
  };
}
