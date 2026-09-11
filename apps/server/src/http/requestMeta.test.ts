/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { clientAddress } from "./requestMeta.js";

describe("clientAddress", () => {
  it("uses the socket address and ignores XFF when no proxy is trusted", () => {
    // The header is caller-supplied unless a proxy is declared, so with none
    // declared the socket address is the only value with provenance.
    expect(clientAddress("1.2.3.4", "10.0.0.9", 0)).toBe("10.0.0.9");
    expect(clientAddress("1.2.3.4", undefined, 0)).toBeUndefined();
  });

  it("counts back through the trusted proxies", () => {
    // Two trusted proxies appended the last two entries; what they observed of
    // the caller is the entry just before them.
    expect(
      clientAddress("spoofed, 198.51.100.7, 10.0.0.1", "10.0.0.2", 2),
    ).toBe("198.51.100.7");
    expect(clientAddress("198.51.100.7", "10.0.0.2", 1)).toBe("198.51.100.7");
  });

  it("falls back to the socket address when the chain is shorter than trusted", () => {
    // A caller-supplied header that names fewer proxies than the deployment has
    // is forged; the socket address is the only thing left to believe.
    expect(clientAddress("spoofed", "10.0.0.2", 2)).toBe("10.0.0.2");
    expect(clientAddress("spoofed", undefined, 2)).toBeUndefined();
  });

  it("keeps the socket address when no header was sent", () => {
    expect(clientAddress(undefined, "10.0.0.2", 1)).toBe("10.0.0.2");
  });

  it("sanitises the entry it chooses", () => {
    expect(clientAddress("bad\u0000value", "10.0.0.2", 1)).toBe("badvalue");
  });
});
