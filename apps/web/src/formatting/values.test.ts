/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  capabilityLabel,
  clientTypeLabel,
  countOf,
  formatDuration,
  formatInstant,
  formatSince,
  pluralise,
  truncate,
} from "./values.js";

describe("formatInstant", () => {
  it("formats a timestamp", () => {
    const formatted = formatInstant("2026-08-04T06:30:00.000Z");
    expect(formatted).toContain("2026");
    expect(formatted).toContain("Aug");
  });

  it("says never rather than showing a null", () => {
    expect(formatInstant(null)).toBe("never");
    expect(formatInstant(undefined)).toBe("never");
  });

  it("passes through a value it cannot parse", () => {
    // Better to show the server's value than to claim it is invalid.
    expect(formatInstant("not a date")).toBe("not a date");
  });
});

describe("formatSince", () => {
  const now = new Date("2026-08-04T12:00:00.000Z");

  it("treats the last few seconds as just now", () => {
    expect(formatSince("2026-08-04T11:59:50.000Z", now)).toBe("just now");
  });

  it("counts minutes", () => {
    expect(formatSince("2026-08-04T11:57:00.000Z", now)).toBe("3 minutes ago");
  });

  it("agrees in the singular", () => {
    expect(formatSince("2026-08-04T11:00:00.000Z", now)).toBe("1 hour ago");
  });

  it("counts days", () => {
    expect(formatSince("2026-08-01T12:00:00.000Z", now)).toBe("3 days ago");
  });

  it("does not claim a future timestamp is in the past", () => {
    // Clock skew between the server and the browser is normal, and "in 3 minutes"
    // beats "-3 minutes ago".
    expect(formatSince("2026-08-04T12:05:00.000Z", now)).toBe("in the future");
  });

  it("says never for an absent value", () => {
    expect(formatSince(null, now)).toBe("never");
  });
});

describe("formatDuration", () => {
  it("uses the largest whole unit", () => {
    expect(formatDuration(300)).toBe("5 minutes");
    expect(formatDuration(3600)).toBe("1 hour");
    expect(formatDuration(2_592_000)).toBe("30 days");
  });

  it("keeps one decimal where the unit does not divide evenly", () => {
    expect(formatDuration(5400)).toBe("1.5 hours");
  });

  it("handles zero and nonsense without throwing", () => {
    expect(formatDuration(0)).toBe("0 seconds");
    expect(formatDuration(Number.NaN)).toBe("0 seconds");
  });
});

describe("pluralise and countOf", () => {
  it("agrees with the count", () => {
    expect(pluralise("client", 1)).toBe("client");
    expect(pluralise("client", 2)).toBe("clients");
    expect(countOf(0, "key")).toBe("0 keys");
    expect(countOf(1, "key")).toBe("1 key");
  });
});

describe("capabilityLabel", () => {
  it("drops the prefix and keeps acronyms", () => {
    expect(capabilityLabel("supportsEhrLaunch")).toBe("EHR launch");
  });

  it("capitalises only the first word", () => {
    expect(capabilityLabel("supportsStandaloneLaunch")).toBe(
      "Standalone launch",
    );
    expect(capabilityLabel("allowsPublicClients")).toBe("Public clients");
  });

  it("states the few labels that would read badly", () => {
    expect(capabilityLabel("supportsOpenIdConnect")).toBe(
      "OpenID Connect single sign-on",
    );
  });

  it("handles a version acronym", () => {
    expect(capabilityLabel("supportsV2Scopes")).toBe("v2 scopes");
  });

  it("falls back to the name when there is nothing to derive", () => {
    expect(capabilityLabel("supports")).toBe("supports");
  });
});

describe("clientTypeLabel", () => {
  it("names the three postures", () => {
    expect(clientTypeLabel("public")).toBe("Public");
    expect(clientTypeLabel("confidential-symmetric")).toBe(
      "Confidential (secret)",
    );
    expect(clientTypeLabel("confidential-asymmetric")).toBe(
      "Confidential (key)",
    );
  });

  it("passes through a type it does not know", () => {
    expect(clientTypeLabel("something-new")).toBe("something-new");
  });
});

describe("truncate", () => {
  it("leaves a short value alone", () => {
    expect(truncate("short")).toBe("short");
  });

  it("keeps the start, which is the distinguishing part", () => {
    expect(truncate("abcdefghij", 5)).toBe("abcd…");
  });
});
