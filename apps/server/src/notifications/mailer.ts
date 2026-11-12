/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Sending email through the deployment's SMTP relay.
 *
 * SMTP rather than a provider's API, so one configuration serves Amazon SES, a
 * hospital's own relay and a local mail catcher alike. The relay's address comes
 * from the operator's environment, never from a request, which is why this is not
 * routed through `outboundFetch`: that guard exists for addresses somebody else
 * supplied.
 *
 * Author: John Grimes
 */

import nodemailer from "nodemailer";

import type { SmtpConfig } from "../config.js";

/** One addressed plain-text email. */
export interface OutgoingEmail {
  readonly to: string;
  readonly subject: string;
  readonly text: string;
}

/**
 * Sends one email, resolving once the relay has accepted it.
 *
 * Rejects when the relay cannot be reached, will not upgrade to TLS when that is
 * required, refuses the credentials, or refuses the recipient.
 */
export type Mailer = (email: OutgoingEmail) => Promise<void>;

/**
 * How long each stage of a conversation may take.
 *
 * Nodemailer's defaults allow minutes, and a notification is sent in the background
 * of a request that has already been answered - so a relay that has gone quiet
 * would hold a socket open for that long per message. Seconds are plenty for a
 * relay that is working.
 */
const TIMEOUTS = {
  connectionTimeout: 10_000,
  greetingTimeout: 10_000,
  socketTimeout: 30_000,
} as const;

/**
 * Creates a mailer over SMTP.
 *
 * @param config - The relay to send through. See `SmtpConfig.tls` for what each
 *   protection level permits.
 * @returns The mailer. It opens a connection per message rather than keeping a
 *   pool, because notifications are rare and an idle pooled connection is one
 *   the relay will drop anyway.
 * @example
 * ```ts
 * const send = createSmtpMailer(config.smtp);
 * await send({ to: "owner@example.org", subject, text });
 * ```
 */
export function createSmtpMailer(config: SmtpConfig): Mailer {
  const transport = nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.tls === "implicit",
    requireTLS: config.tls === "starttls",
    ...(config.credentials === undefined
      ? {}
      : {
          auth: {
            user: config.credentials.username,
            pass: config.credentials.password,
          },
        }),
    // The messages carry text and nothing else; these stop a future attachment
    // or alternative from turning into a read of the filesystem or a fetch.
    disableFileAccess: true,
    disableUrlAccess: true,
    ...TIMEOUTS,
  });

  return async (email) => {
    await transport.sendMail({
      from: config.from,
      to: email.to,
      subject: email.subject,
      text: email.text,
    });
  };
}
