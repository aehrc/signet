/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * What a tenant may upload as its logo.
 *
 * A tenant may hold two logos: the one shown by default, and an optional variant
 * shown when the reader's operating system asks for a dark colour scheme. Either is
 * a PNG, JPEG, WebP or SVG of at most {@link MAX_LOGO_BYTES}.
 *
 * The media type is decided from the bytes rather than taken from the upload's
 * `Content-Type`. The stored type is what the logo is later served as, on the same
 * origin as the console, so a type the uploader merely asserted would let any file be
 * served under an image's name. Sniffing here, once, means the server stores and
 * the console checks the same answer.
 *
 * Author: John Grimes
 */

/** The two logos a tenant may hold. */
export const LOGO_VARIANTS = ["light", "dark"] as const;

/**
 * One of the logo variants.
 *
 * `light` is the logo itself, shown whenever the tenant has one. `dark` is shown in
 * its place when the reader's system prefers a dark colour scheme, and is meaningful
 * only alongside a `light` logo.
 */
export type LogoVariant = (typeof LOGO_VARIANTS)[number];

/** The media types a logo may be stored and served as. */
export type LogoMediaType =
  "image/png" | "image/jpeg" | "image/webp" | "image/svg+xml";

/**
 * The largest logo accepted, in bytes.
 *
 * 256 KiB, which is generous for a logo and equal to the server's request body cap,
 * so a logo at the limit can still be uploaded as a raw request body.
 */
export const MAX_LOGO_BYTES = 262_144;

/** The outcome of inspecting an uploaded logo. */
export type LogoInspection =
  | { readonly ok: true; readonly mediaType: LogoMediaType }
  | {
      readonly ok: false;
      readonly problem: "empty" | "too-large" | "unsupported";
    };

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const JPEG_SIGNATURE = [0xff, 0xd8, 0xff];
/** "RIFF", then a four-byte length, then "WEBP". */
const RIFF_SIGNATURE = [0x52, 0x49, 0x46, 0x46];
const WEBP_FORM_TYPE = [0x57, 0x45, 0x42, 0x50];

/**
 * An SVG document: an `svg` root element, preceded by nothing but an optional byte
 * order mark, whitespace, an XML declaration, comments and a doctype.
 *
 * Anchored to the root element rather than searching for `<svg` anywhere, because an
 * HTML page containing an inline SVG is not an SVG document and must not be stored
 * as one. Case-sensitive, as XML is: `<SVG>` is not an SVG element.
 *
 * Every part of the prolog can end in exactly one place - a comment at its first
 * `-->`, a declaration at its first `?>`, a doctype at its first `>` or, with an
 * internal subset, the first `>` after its first `]` - and the alternatives begin
 * differently. That is what keeps a failed match linear. A lazy `[\s\S]*?` would let
 * each part end at any later terminator, and a few hundred bytes of comments with no
 * root element after them would then be retried in exponentially many ways, holding
 * the server's only thread for as long as that takes.
 */
const SVG_DOCUMENT =
  /^\uFEFF?(?:\s|<\?xml(?:(?!\?>)[\s\S])*\?>|<!--(?:(?!-->)[\s\S])*-->|<!DOCTYPE[^>[]*(?:\[[^\]]*\]\s*)?>)*<svg[\s/>]/;

/** Whether `bytes` holds `signature` starting at `offset`. */
function hasBytesAt(
  bytes: Uint8Array,
  signature: readonly number[],
  offset = 0,
): boolean {
  return signature.every((value, index) => bytes[offset + index] === value);
}

/**
 * Decides whether an uploaded file is acceptable as a logo, and what it is.
 *
 * @param bytes - The file's content.
 * @returns The media type the file is, or the reason it is refused: `empty` for no
 *   content, `too-large` for more than {@link MAX_LOGO_BYTES}, and `unsupported`
 *   for anything that is not a PNG, JPEG, WebP or SVG document.
 * @example
 * ```ts
 * const inspection = inspectLogo(new Uint8Array(await file.arrayBuffer()));
 * if (!inspection.ok) {
 *   console.log(inspection.problem); // "unsupported"
 * }
 * ```
 */
export function inspectLogo(bytes: Uint8Array): LogoInspection {
  if (bytes.length === 0) {
    return { ok: false, problem: "empty" };
  }
  if (bytes.length > MAX_LOGO_BYTES) {
    return { ok: false, problem: "too-large" };
  }
  if (hasBytesAt(bytes, PNG_SIGNATURE)) {
    return { ok: true, mediaType: "image/png" };
  }
  if (hasBytesAt(bytes, JPEG_SIGNATURE)) {
    return { ok: true, mediaType: "image/jpeg" };
  }
  if (
    hasBytesAt(bytes, RIFF_SIGNATURE) &&
    hasBytesAt(bytes, WEBP_FORM_TYPE, 8)
  ) {
    return { ok: true, mediaType: "image/webp" };
  }
  if (SVG_DOCUMENT.test(new TextDecoder().decode(bytes))) {
    return { ok: true, mediaType: "image/svg+xml" };
  }
  return { ok: false, problem: "unsupported" };
}

/**
 * Whether a string names a logo variant, as a path segment does.
 *
 * @param value - The candidate, typically from a URL.
 * @returns True for `light` and `dark` only.
 */
export function isLogoVariant(value: string): value is LogoVariant {
  return (LOGO_VARIANTS as readonly string[]).includes(value);
}

/**
 * Says why a logo was refused, in words an operator can act on.
 *
 * Shared by the server's refusal and the console's check before uploading, so the
 * two say the same thing.
 *
 * @param problem - The reason {@link inspectLogo} gave.
 * @returns One sentence.
 */
export function describeLogoProblem(
  problem: Extract<LogoInspection, { ok: false }>["problem"],
): string {
  switch (problem) {
    case "empty": {
      return "The file is empty.";
    }
    case "too-large": {
      return `A logo may be at most ${String(MAX_LOGO_BYTES / 1024)} KB.`;
    }
    case "unsupported": {
      return "A logo must be a PNG, JPEG, WebP or SVG image.";
    }
  }
}
