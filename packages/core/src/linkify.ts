/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Finding the links in a piece of plain text.
 *
 * An endpoint's login message is plain text written by an operator, typically
 * something like "Contact us at pathling@csiro.au if you want an account." The
 * sign-in page makes the addresses in it clickable. Plain text rather than Markdown
 * or HTML, so there is no markup to sanitise: the page renders each segment as text
 * or as a link whose `href` this function built, and only `http:`, `https:` and
 * `mailto:` hrefs are ever produced.
 *
 * Author: John Grimes
 */

/** A run of plain text, or a link to show in place of the text it was found in. */
export type TextSegment =
  | { readonly kind: "text"; readonly text: string }
  | { readonly kind: "link"; readonly text: string; readonly href: string };

/**
 * An http(s) URL, or an email address.
 *
 * The URL alternative comes first, so a URL carrying credentials
 * (`https://user@host`) is matched as a URL rather than having an email address
 * found inside it. A URL may not end in punctuation that usually closes the
 * sentence or bracket around it.
 */
const LINK_PATTERN =
  /(https?:\/\/[^\s<>"]*[^\s<>".,;:!?'")\]}])|([A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})/g;

/**
 * Splits plain text into text and link segments.
 *
 * @param text - The text to scan.
 * @returns The segments in order; concatenating their `text` gives back the input.
 * @example
 * linkifyText("Email a@b.org.");
 * // [{ kind: "text", text: "Email " },
 * //  { kind: "link", text: "a@b.org", href: "mailto:a@b.org" },
 * //  { kind: "text", text: "." }]
 */
export function linkifyText(text: string): readonly TextSegment[] {
  const segments: TextSegment[] = [];
  let position = 0;
  for (const match of text.matchAll(LINK_PATTERN)) {
    const [found, url] = match;
    if (match.index > position) {
      segments.push({ kind: "text", text: text.slice(position, match.index) });
    }
    segments.push({
      kind: "link",
      text: found,
      href: url === undefined ? `mailto:${found}` : found,
    });
    position = match.index + found.length;
  }
  if (position < text.length) {
    segments.push({ kind: "text", text: text.slice(position) });
  }
  return segments;
}
