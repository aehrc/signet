/**
 * Author: John Grimes
 */

import { describe, expect, it, vi } from "vitest";

import { logRecord, shouldLog } from "./log.js";

describe("shouldLog", () => {
  it("emits a record at the configured level", () => {
    expect(shouldLog("info", "info")).toBe(true);
  });

  it("emits a record above the configured level", () => {
    expect(shouldLog("info", "error")).toBe(true);
  });

  it("suppresses a record below the configured level", () => {
    expect(shouldLog("info", "debug")).toBe(false);
  });

  it("suppresses warnings when only errors are wanted", () => {
    expect(shouldLog("error", "warn")).toBe(false);
  });

  it("emits everything at debug", () => {
    for (const level of ["debug", "info", "warn", "error"] as const) {
      expect(shouldLog("debug", level)).toBe(true);
    }
  });
});

describe("logRecord", () => {
  it("writes one line of JSON carrying the level and message", () => {
    const written: string[] = [];
    const spy = vi
      .spyOn(console, "log")
      .mockImplementation((line: unknown) => written.push(String(line)));

    logRecord("info", "info", "signet.test", { a: 1 });
    spy.mockRestore();

    expect(written).toHaveLength(1);
    expect(JSON.parse(written[0] ?? "{}")).toEqual({
      level: "info",
      message: "signet.test",
      a: 1,
    });
  });

  it("writes warnings and errors to stderr", () => {
    const written: string[] = [];
    const spy = vi
      .spyOn(console, "error")
      .mockImplementation((line: unknown) => written.push(String(line)));

    logRecord("debug", "warn", "signet.warned");
    spy.mockRestore();

    expect(written).toHaveLength(1);
  });

  it("writes nothing when the threshold suppresses the record", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const error = vi
      .spyOn(console, "error")
      .mockImplementation(() => undefined);

    logRecord("error", "info", "signet.quiet");

    expect(log).not.toHaveBeenCalled();
    expect(error).not.toHaveBeenCalled();
    log.mockRestore();
    error.mockRestore();
  });
});
