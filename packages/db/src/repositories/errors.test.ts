import { describe, expect, it } from "vitest";

import {
  DEADLOCK_DETECTED,
  isForeignKeyViolation,
  isRetryableTransactionError,
  isUniqueViolation,
  SERIALIZATION_FAILURE,
  sqlStateOf,
  UNIQUE_VIOLATION,
} from "./errors.js";

/** A driver error as it arrives from postgres-js, reduced to what is read. */
function driverError(code: string, constraint?: string): unknown {
  return constraint === undefined
    ? { code }
    : { code, constraint_name: constraint };
}

describe("sqlStateOf", () => {
  it("reads the SQLSTATE from a driver error", () => {
    expect(sqlStateOf(driverError(UNIQUE_VIOLATION))).toBe("23505");
  });

  it("returns undefined for values that are not errors", () => {
    expect(sqlStateOf(undefined)).toBeUndefined();
    expect(sqlStateOf(null)).toBeUndefined();
    expect(sqlStateOf("boom")).toBeUndefined();
    expect(sqlStateOf(new Error("boom"))).toBeUndefined();
  });

  it("ignores a non-string code", () => {
    expect(sqlStateOf({ code: 23_505 })).toBeUndefined();
  });
});

describe("isUniqueViolation", () => {
  it("recognises a unique violation", () => {
    expect(isUniqueViolation(driverError(UNIQUE_VIOLATION))).toBe(true);
  });

  it("does not mistake another constraint class for one", () => {
    expect(isUniqueViolation(driverError("23503"))).toBe(false);
  });

  it("requires the named constraint when one is given", () => {
    const error = driverError(UNIQUE_VIOLATION, "jti_replay_pk");
    expect(isUniqueViolation(error, "jti_replay_pk")).toBe(true);
    expect(
      isUniqueViolation(error, "policies_endpoint_id_version_unique"),
    ).toBe(false);
  });

  it("does not match a named constraint when the error names none", () => {
    expect(
      isUniqueViolation(driverError(UNIQUE_VIOLATION), "jti_replay_pk"),
    ).toBe(false);
  });
});

describe("isForeignKeyViolation", () => {
  it("recognises a foreign key violation", () => {
    expect(isForeignKeyViolation(driverError("23503"))).toBe(true);
    expect(isForeignKeyViolation(driverError(UNIQUE_VIOLATION))).toBe(false);
  });
});

describe("isRetryableTransactionError", () => {
  it("recognises the two failures a retry can resolve", () => {
    expect(
      isRetryableTransactionError(driverError(SERIALIZATION_FAILURE)),
    ).toBe(true);
    expect(isRetryableTransactionError(driverError(DEADLOCK_DETECTED))).toBe(
      true,
    );
  });

  it("does not invite a retry of a constraint violation", () => {
    // Retrying a unique violation would loop for ever: the conflicting row is
    // still there.
    expect(isRetryableTransactionError(driverError(UNIQUE_VIOLATION))).toBe(
      false,
    );
  });
});
