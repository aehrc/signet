/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { isScriptFreeUri } from "@signet/core";
import { describe, expect, it } from "bun:test";

import { redirectUriSchema, webUriSchema } from "./primitives.js";

describe("redirectUriSchema", () => {
  it("accepts an https redirect URI", () => {
    expect(
      redirectUriSchema.safeParse("https://app.example.org/callback").success,
    ).toBe(true);
  });

  it("accepts an http redirect URI on a loopback address", () => {
    for (const uri of [
      "http://127.0.0.1:9000/callback",
      "http://[::1]/callback",
      "http://localhost/callback",
    ]) {
      expect(redirectUriSchema.safeParse(uri).success).toBe(true);
    }
  });

  it("accepts a private-use scheme, which RFC 8252 native apps redirect to", () => {
    expect(redirectUriSchema.safeParse("org.example.app:/oauth").success).toBe(
      true,
    );
  });

  it("refuses a scheme a browser would execute", () => {
    for (const uri of [
      "javascript:alert(1)",
      "data:text/html,<script>alert(1)</script>",
      "vbscript:msgbox(1)",
      "blob:https://app.example.org/00000000",
    ]) {
      expect(redirectUriSchema.safeParse(uri).success).toBe(false);
    }
  });

  it("refuses plain http on a public host", () => {
    expect(
      redirectUriSchema.safeParse("http://app.example.org/callback").success,
    ).toBe(false);
  });

  it("refuses schemes that open local content", () => {
    for (const uri of ["file:///etc/passwd", "ftp://example.org/pub"]) {
      expect(redirectUriSchema.safeParse(uri).success).toBe(false);
    }
  });
});

describe("webUriSchema", () => {
  it("accepts https and http URLs", () => {
    for (const uri of [
      "https://app.example.org/launch",
      "http://intranet.example.org/launch",
    ]) {
      expect(webUriSchema.safeParse(uri).success).toBe(true);
    }
  });

  it("refuses a scheme a browser would execute", () => {
    for (const uri of [
      "javascript:alert(1)",
      "data:image/svg+xml,<svg onload=alert(1)>",
      "vbscript:msgbox(1)",
    ]) {
      expect(webUriSchema.safeParse(uri).success).toBe(false);
    }
  });
});

describe("isScriptFreeUri", () => {
  it("refuses exactly the schemes that execute in a browser", () => {
    expect(isScriptFreeUri("https://app.example.org/callback")).toBe(true);
    expect(isScriptFreeUri("org.example.app:/oauth")).toBe(true);
    expect(isScriptFreeUri("javascript:alert(1)")).toBe(false);
    expect(isScriptFreeUri("DATA:text/html,<script>alert(1)</script>")).toBe(
      false,
    );
    expect(isScriptFreeUri("vbscript:msgbox(1)")).toBe(false);
    expect(isScriptFreeUri("blob:https://app.example.org/00000000")).toBe(
      false,
    );
  });
});
