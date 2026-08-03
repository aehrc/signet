import { describe, expect, it } from "vitest";

import { ConfigError, loadConfig, type Environment } from "./config.js";

const MASTER_KEY = "0123456789abcdef0123456789abcdef";

/** A minimal valid environment, overridable per test. */
function env(overrides: Environment = {}): Environment {
  return {
    SIGNET_PUBLIC_URL: "https://signet.example.org",
    SIGNET_DATABASE_URL: "postgres://u:p@db:5432/signet",
    SIGNET_MASTER_KEY: MASTER_KEY,
    ...overrides,
  };
}

describe("loadConfig — defaults", () => {
  it("resolves a minimal valid environment", () => {
    expect(loadConfig(env())).toEqual({
      port: 3000,
      publicUrl: "https://signet.example.org",
      databaseUrl: "postgres://u:p@db:5432/signet",
      masterKey: MASTER_KEY,
      logLevel: "info",
    });
  });

  it("reads the port", () => {
    expect(loadConfig(env({ PORT: "8080" })).port).toBe(8080);
  });

  it("rejects a non-numeric or out-of-range port", () => {
    expect(() => loadConfig(env({ PORT: "http" }))).toThrow(ConfigError);
    expect(() => loadConfig(env({ PORT: "0" }))).toThrow(ConfigError);
    expect(() => loadConfig(env({ PORT: "70000" }))).toThrow(ConfigError);
  });
});

describe("loadConfig — public URL", () => {
  it("strips trailing slashes so issuers concatenate predictably", () => {
    expect(
      loadConfig(env({ SIGNET_PUBLIC_URL: "https://s.example.org/" }))
        .publicUrl,
    ).toBe("https://s.example.org");
    expect(
      loadConfig(env({ SIGNET_PUBLIC_URL: "https://s.example.org///" }))
        .publicUrl,
    ).toBe("https://s.example.org");
  });

  it("preserves a path prefix", () => {
    expect(
      loadConfig(env({ SIGNET_PUBLIC_URL: "https://s.example.org/auth" }))
        .publicUrl,
    ).toBe("https://s.example.org/auth");
  });

  it("is required", () => {
    expect(() => loadConfig(env({ SIGNET_PUBLIC_URL: undefined }))).toThrow(
      /SIGNET_PUBLIC_URL is required/,
    );
  });

  it("treats a blank value as absent", () => {
    expect(() => loadConfig(env({ SIGNET_PUBLIC_URL: "   " }))).toThrow(
      /SIGNET_PUBLIC_URL is required/,
    );
  });

  it("rejects a malformed URL", () => {
    expect(() => loadConfig(env({ SIGNET_PUBLIC_URL: "not a url" }))).toThrow(
      /not a valid URL/,
    );
  });

  it("rejects a non-HTTP scheme", () => {
    expect(() =>
      loadConfig(env({ SIGNET_PUBLIC_URL: "ftp://s.example.org" })),
    ).toThrow(/must be http or https/);
  });
});

describe("loadConfig — database from discrete parts", () => {
  // This is the shape the Helm chart uses with the bundled PostgreSQL subchart,
  // where the password comes from the subchart's own secret.
  const parts: Environment = {
    SIGNET_DATABASE_URL: undefined,
    SIGNET_DATABASE_HOST: "release-postgresql",
    SIGNET_DATABASE_PORT: "5432",
    SIGNET_DATABASE_NAME: "signet",
    SIGNET_DATABASE_USER: "signet",
    SIGNET_DATABASE_PASSWORD: "s3cret",
  };

  it("composes a connection URL", () => {
    expect(loadConfig(env(parts)).databaseUrl).toBe(
      "postgres://signet:s3cret@release-postgresql:5432/signet",
    );
  });

  it("defaults the port to 5432", () => {
    expect(
      loadConfig(env({ ...parts, SIGNET_DATABASE_PORT: undefined }))
        .databaseUrl,
    ).toContain(":5432/");
  });

  it("percent-encodes a password containing URL-significant characters", () => {
    // A generated password containing `@` or `/` would otherwise terminate the
    // userinfo component and point the server at a different host entirely.
    const config = loadConfig(
      env({ ...parts, SIGNET_DATABASE_PASSWORD: "p@ss/w:rd?#" }),
    );
    expect(config.databaseUrl).toBe(
      "postgres://signet:p%40ss%2Fw%3Ard%3F%23@release-postgresql:5432/signet",
    );
    expect(new URL(config.databaseUrl).hostname).toBe("release-postgresql");
    expect(new URL(config.databaseUrl).password).toBe("p%40ss%2Fw%3Ard%3F%23");
  });

  it("omits the password when none is supplied", () => {
    expect(
      loadConfig(env({ ...parts, SIGNET_DATABASE_PASSWORD: undefined }))
        .databaseUrl,
    ).toBe("postgres://signet@release-postgresql:5432/signet");
  });

  it("requires name and user alongside host", () => {
    expect(() =>
      loadConfig(env({ ...parts, SIGNET_DATABASE_NAME: undefined })),
    ).toThrow(
      /SIGNET_DATABASE_NAME and SIGNET_DATABASE_USER are also required/,
    );
    expect(() =>
      loadConfig(env({ ...parts, SIGNET_DATABASE_USER: undefined })),
    ).toThrow(
      /SIGNET_DATABASE_NAME and SIGNET_DATABASE_USER are also required/,
    );
  });

  it("rejects a non-numeric port", () => {
    expect(() =>
      loadConfig(env({ ...parts, SIGNET_DATABASE_PORT: "abc" })),
    ).toThrow(/must be a number/);
  });
});

describe("loadConfig — database validation", () => {
  it("rejects supplying both a URL and discrete parts", () => {
    expect(() =>
      loadConfig(
        env({
          SIGNET_DATABASE_HOST: "db",
          SIGNET_DATABASE_NAME: "signet",
          SIGNET_DATABASE_USER: "signet",
        }),
      ),
    ).toThrow(/not both/);
  });

  it("requires one of them", () => {
    expect(() => loadConfig(env({ SIGNET_DATABASE_URL: undefined }))).toThrow(
      /SIGNET_DATABASE_URL or SIGNET_DATABASE_HOST is required/,
    );
  });
});

describe("loadConfig — master key", () => {
  it("is required", () => {
    expect(() => loadConfig(env({ SIGNET_MASTER_KEY: undefined }))).toThrow(
      /SIGNET_MASTER_KEY is required/,
    );
  });

  it("rejects a key that is too short to be a useful envelope key", () => {
    expect(() => loadConfig(env({ SIGNET_MASTER_KEY: "short" }))).toThrow(
      /at least 32 characters/,
    );
  });

  it("accepts exactly 32 characters", () => {
    expect(
      loadConfig(env({ SIGNET_MASTER_KEY: "a".repeat(32) })).masterKey,
    ).toHaveLength(32);
  });
});

describe("loadConfig — log level", () => {
  it.each(["debug", "info", "warn", "error"])("accepts %s", (level) => {
    expect(loadConfig(env({ SIGNET_LOG_LEVEL: level })).logLevel).toBe(level);
  });

  it("rejects an unknown level", () => {
    expect(() => loadConfig(env({ SIGNET_LOG_LEVEL: "verbose" }))).toThrow(
      /must be one of/,
    );
  });
});
