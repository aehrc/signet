/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The operator's message on the sign-in page, such as who to contact for an account.
 *
 * Plain text with its line breaks kept, and with email addresses and web addresses
 * made into links by `linkifyText`. Every piece is rendered as a React text node or
 * as a link whose `href` that function built, so nothing in the message is ever
 * interpreted as markup.
 *
 * Author: John Grimes
 */

import { linkifyText } from "@signet/core";

import { InfoAlert } from "../components/layout.js";

/**
 * Shows an endpoint's login message, or nothing when it has none.
 *
 * @param props - The props.
 * @param props.message - The message, or null.
 * @returns The message in an info box, or null.
 */
export function LoginMessage({
  message,
}: Readonly<{ message: string | null }>) {
  if (message === null) {
    return null;
  }
  return (
    <InfoAlert>
      {/* `wrap-anywhere` lets a long URL or address break, where `break-words` alone
          leaves the alert as wide as the longest word. */}
      <p className="whitespace-pre-line wrap-anywhere">
        {linkifyText(message).map((segment, index) =>
          segment.kind === "text" ? (
            segment.text
          ) : (
            // The segments never reorder, so the index is a stable key.
            <a key={index} className="link" href={segment.href}>
              {segment.text}
            </a>
          ),
        )}
      </p>
    </InfoAlert>
  );
}
