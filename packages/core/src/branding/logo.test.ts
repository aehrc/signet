/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * What a tenant may upload as its logo.
 *
 * The media type is decided from the bytes, not from whatever the uploader said
 * they were, because the stored type is what the logo is later served as - and an
 * HTML document accepted as `image/png` and served back as something a browser
 * sniffs into a page is exactly the mistake these tests exist to rule out.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { inspectLogo, isLogoVariant, MAX_LOGO_BYTES } from "./logo.js";

/** Encodes text as the bytes an uploaded file would carry. */
function bytesOf(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** Joins byte arrays, for a file that begins with a signature. */
function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.length;
  }
  return joined;
}

const PNG_SIGNATURE = Uint8Array.of(
  0x89,
  0x50,
  0x4e,
  0x47,
  0x0d,
  0x0a,
  0x1a,
  0x0a,
);
const JPEG_SIGNATURE = Uint8Array.of(0xff, 0xd8, 0xff, 0xe0);

/** A file whose bytes start with a signature and carry some payload after it. */
function fileStartingWith(signature: Uint8Array, length = 64): Uint8Array {
  return concat(signature, new Uint8Array(length - signature.length));
}

describe("inspectLogo", () => {
  describe("raster formats", () => {
    it("recognises a PNG by its eight-byte signature", () => {
      expect(inspectLogo(fileStartingWith(PNG_SIGNATURE))).toEqual({
        ok: true,
        mediaType: "image/png",
      });
    });

    it("recognises a JPEG by its start-of-image marker", () => {
      expect(inspectLogo(fileStartingWith(JPEG_SIGNATURE))).toEqual({
        ok: true,
        mediaType: "image/jpeg",
      });
    });

    it("recognises a WebP by its RIFF container and WEBP form type", () => {
      const webp = concat(
        bytesOf("RIFF"),
        Uint8Array.of(0x24, 0, 0, 0),
        bytesOf("WEBPVP8 "),
        new Uint8Array(32),
      );
      expect(inspectLogo(webp)).toEqual({ ok: true, mediaType: "image/webp" });
    });

    it("refuses a RIFF container that is not a WebP", () => {
      // A WAV file shares the RIFF header and differs only in the form type.
      const wav = concat(
        bytesOf("RIFF"),
        Uint8Array.of(0x24, 0, 0, 0),
        bytesOf("WAVEfmt "),
        new Uint8Array(32),
      );
      expect(inspectLogo(wav)).toEqual({ ok: false, problem: "unsupported" });
    });

    it("refuses a GIF, which is not one of the accepted formats", () => {
      expect(inspectLogo(fileStartingWith(bytesOf("GIF89a")))).toEqual({
        ok: false,
        problem: "unsupported",
      });
    });

    it("refuses a truncated PNG signature", () => {
      expect(inspectLogo(PNG_SIGNATURE.slice(0, 4))).toEqual({
        ok: false,
        problem: "unsupported",
      });
    });
  });

  describe("SVG", () => {
    it("recognises a bare svg element", () => {
      expect(
        inspectLogo(bytesOf('<svg xmlns="http://www.w3.org/2000/svg"></svg>')),
      ).toEqual({ ok: true, mediaType: "image/svg+xml" });
    });

    it("recognises an svg element behind an XML declaration, comments and a doctype", () => {
      // What a design tool typically exports.
      const exported = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        "<!-- Generator: Some Design Tool -->",
        '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">',
        '<svg version="1.1" xmlns="http://www.w3.org/2000/svg">',
        "</svg>",
      ].join("\n");
      expect(inspectLogo(bytesOf(exported))).toEqual({
        ok: true,
        mediaType: "image/svg+xml",
      });
    });

    it("recognises an svg element preceded by a byte order mark and whitespace", () => {
      expect(inspectLogo(bytesOf("\uFEFF \n\t<svg></svg>"))).toEqual({
        ok: true,
        mediaType: "image/svg+xml",
      });
    });

    it("refuses an HTML document that merely contains an svg element", () => {
      // Accepting this would store a page as an image.
      expect(
        inspectLogo(bytesOf("<html><body><svg></svg></body></html>")),
      ).toEqual({ ok: false, problem: "unsupported" });
    });

    it("refuses an element whose name only starts with svg", () => {
      expect(inspectLogo(bytesOf("<svgfoo></svgfoo>"))).toEqual({
        ok: false,
        problem: "unsupported",
      });
    });

    it("refuses plain text", () => {
      expect(inspectLogo(bytesOf("not an image"))).toEqual({
        ok: false,
        problem: "unsupported",
      });
    });
  });

  describe("pathological prologs", () => {
    /**
     * Inspects a file and reports how long it took.
     *
     * The bound is loose enough for a slow CI runner and still orders of magnitude
     * below what backtracking costs: each of these inputs is a prolog with no root
     * element after it, which a pattern able to end a comment, declaration or doctype
     * at more than one place retries in exponentially many ways.
     */
    function timedInspection(text: string): {
      readonly problem: string | undefined;
      readonly milliseconds: number;
    } {
      const started = performance.now();
      const inspection = inspectLogo(bytesOf(text));
      return {
        problem: inspection.ok ? undefined : inspection.problem,
        milliseconds: performance.now() - started,
      };
    }

    it.each([
      ["comments", "<!---->"],
      ["XML declarations", "<?xml?>"],
      ["doctypes with internal subsets", "<!DOCTYPE[]>"],
      ["doctypes with trailing whitespace", "<!DOCTYPE svg   >"],
    ])(
      "refuses thirty %s with no root element without backtracking",
      (_name, fragment) => {
        const { problem, milliseconds } = timedInspection(
          `${fragment.repeat(30)}x`,
        );
        expect(problem).toBe("unsupported");
        expect(milliseconds).toBeLessThan(1000);
      },
    );

    it.each([
      ["comments", "<!---->"],
      ["XML declarations", "<?xml?>"],
      ["doctypes with internal subsets", "<!DOCTYPE[]>"],
      ["whitespace", " "],
    ])(
      "refuses a prolog of %s filling the size limit in linear time",
      (_name, fragment) => {
        const count = Math.floor((MAX_LOGO_BYTES - 1) / fragment.length);
        const { problem, milliseconds } = timedInspection(
          `${fragment.repeat(count)}x`,
        );
        expect(problem).toBe("unsupported");
        expect(milliseconds).toBeLessThan(1000);
      },
    );
  });

  describe("size", () => {
    it("refuses an empty file", () => {
      expect(inspectLogo(new Uint8Array(0))).toEqual({
        ok: false,
        problem: "empty",
      });
    });

    it("accepts a file of exactly the maximum size", () => {
      expect(
        inspectLogo(fileStartingWith(PNG_SIGNATURE, MAX_LOGO_BYTES)),
      ).toEqual({ ok: true, mediaType: "image/png" });
    });

    it("refuses a file one byte over the maximum, whatever it contains", () => {
      expect(
        inspectLogo(fileStartingWith(PNG_SIGNATURE, MAX_LOGO_BYTES + 1)),
      ).toEqual({ ok: false, problem: "too-large" });
    });
  });
});

describe("isLogoVariant", () => {
  it("accepts the two variants", () => {
    expect(isLogoVariant("light")).toBe(true);
    expect(isLogoVariant("dark")).toBe(true);
  });

  it("refuses anything else, including a differently cased variant", () => {
    expect(isLogoVariant("Light")).toBe(false);
    expect(isLogoVariant("")).toBe(false);
    expect(isLogoVariant("high-contrast")).toBe(false);
  });
});
