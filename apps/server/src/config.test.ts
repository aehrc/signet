/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  ConfigError,
  loadConfig,
  resolveMigrationIdentities,
  resolveSweepConfiguration,
  type Environment,
} from "./config.js";

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

describe("loadConfig - defaults", () => {
  it("resolves a minimal valid environment", () => {
    expect(loadConfig(env())).toEqual({
      port: 3000,
      publicUrl: "https://signet.example.org",
      databaseUrl: "postgres://u:p@db:5432/signet",
      masterKey: MASTER_KEY,
      logLevel: "info",
      webRoot: undefined,
      allowPrivateOutboundFetches: false,
    });
  });

  it("reads the web root", () => {
    expect(loadConfig(env({ SIGNET_WEB_ROOT: "/app/web" })).webRoot).toBe(
      "/app/web",
    );
  });

  it("reads the outbound fetch escape hatch", () => {
    expect(
      loadConfig(env({ SIGNET_ALLOW_PRIVATE_OUTBOUND_FETCHES: "true" }))
        .allowPrivateOutboundFetches,
    ).toBe(true);
    expect(
      loadConfig(env({ SIGNET_ALLOW_PRIVATE_OUTBOUND_FETCHES: "false" }))
        .allowPrivateOutboundFetches,
    ).toBe(false);
  });

  it("refuses a boolean flag it cannot read, rather than defaulting", () => {
    expect(() =>
      loadConfig(env({ SIGNET_ALLOW_PRIVATE_OUTBOUND_FETCHES: "yes" })),
    ).toThrow(ConfigError);
    expect(() =>
      loadConfig(env({ SIGNET_ALLOW_PRIVATE_OUTBOUND_FETCHES: "1" })),
    ).toThrow(ConfigError);
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

describe("loadConfig - public URL", () => {
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

describe("loadConfig - database from discrete parts", () => {
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

describe("loadConfig - database validation", () => {
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

describe("loadConfig - master key", () => {
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

describe("resolveMigrationIdentities", () => {
  // `migrate` is the only command that needs two identities: it applies DDL as
  // the owner, and grants the serving role its access. It never uses the serving
  // password, so the migration job holds no credential it has no use for.
  const identities: Environment = {
    SIGNET_DATABASE_URL: "postgres://signet_app:p@db:5432/signet",
    SIGNET_DATABASE_OWNER_URL: "postgres://signet:owner-p@db:5432/signet",
  };

  it("resolves the owner connection and the role to grant to", () => {
    expect(resolveMigrationIdentities(identities)).toEqual({
      ownerUrl: "postgres://signet:owner-p@db:5432/signet",
      servingRole: "signet_app",
    });
  });

  it("takes the serving role from discrete parts too", () => {
    // The shape the Helm chart uses with the bundled PostgreSQL subchart. The
    // role to grant to is the same question whichever way the connection was
    // configured.
    expect(
      resolveMigrationIdentities({
        SIGNET_DATABASE_HOST: "release-postgresql",
        SIGNET_DATABASE_NAME: "signet",
        SIGNET_DATABASE_USER: "signet_app",
        SIGNET_DATABASE_PASSWORD: "s3cret",
        SIGNET_DATABASE_OWNER_URL: identities["SIGNET_DATABASE_OWNER_URL"],
      }).servingRole,
    ).toBe("signet_app");
  });

  it("decodes a percent-encoded serving username", () => {
    // The composed URL percent-encodes the username, and the grant must name the
    // role the database actually has. Granting to `signet%20app` would succeed
    // as a statement and leave the real role with nothing.
    expect(
      resolveMigrationIdentities({
        ...identities,
        SIGNET_DATABASE_URL: "postgres://signet%20app:p@db:5432/signet",
      }).servingRole,
    ).toBe("signet app");
  });

  it("requires the owner URL, naming it", () => {
    expect(() =>
      resolveMigrationIdentities({
        ...identities,
        SIGNET_DATABASE_OWNER_URL: undefined,
      }),
    ).toThrow(ConfigError);
    expect(() =>
      resolveMigrationIdentities({
        ...identities,
        SIGNET_DATABASE_OWNER_URL: undefined,
      }),
    ).toThrow(/SIGNET_DATABASE_OWNER_URL/);
  });

  it("treats a blank owner URL as absent", () => {
    expect(() =>
      resolveMigrationIdentities({
        ...identities,
        SIGNET_DATABASE_OWNER_URL: "   ",
      }),
    ).toThrow(/SIGNET_DATABASE_OWNER_URL/);
  });

  it("refuses two URLs naming the same role", () => {
    // The refusal that matters. A deployment configured this way applies its
    // migrations and starts a server that owns its tables, which Postgres
    // exempts from the policies - so it would run believing it enforces
    // something it does not.
    expect(() =>
      resolveMigrationIdentities({
        SIGNET_DATABASE_URL: "postgres://signet:p@db:5432/signet",
        SIGNET_DATABASE_OWNER_URL: "postgres://signet:owner-p@db:5432/signet",
      }),
    ).toThrow(/SIGNET_DATABASE_OWNER_URL/);
    expect(() =>
      resolveMigrationIdentities({
        SIGNET_DATABASE_URL: "postgres://signet:p@db:5432/signet",
        SIGNET_DATABASE_OWNER_URL: "postgres://signet:owner-p@db:5432/signet",
      }),
    ).toThrow(/SIGNET_DATABASE_URL/);
  });

  it("refuses a serving URL with no username, naming it", () => {
    // Without one there is nothing to grant to, and the failure would otherwise
    // present much later as a serving role that cannot reach any table.
    expect(() =>
      resolveMigrationIdentities({
        ...identities,
        SIGNET_DATABASE_URL: "postgres://db:5432/signet",
      }),
    ).toThrow(/SIGNET_DATABASE_URL/);
  });

  it("refuses an owner URL with no username, naming it", () => {
    // A connection URL without a username falls back to the operating system
    // user, which cannot be compared against the serving role - so the check
    // above would pass without having checked anything.
    expect(() =>
      resolveMigrationIdentities({
        ...identities,
        SIGNET_DATABASE_OWNER_URL: "postgres://db:5432/signet",
      }),
    ).toThrow(/SIGNET_DATABASE_OWNER_URL/);
  });

  it("refuses an owner URL it cannot parse, naming it", () => {
    expect(() =>
      resolveMigrationIdentities({
        ...identities,
        SIGNET_DATABASE_OWNER_URL: "not a url",
      }),
    ).toThrow(/SIGNET_DATABASE_OWNER_URL/);
  });

  it("refuses a serving URL it cannot parse, naming it", () => {
    expect(() =>
      resolveMigrationIdentities({
        ...identities,
        SIGNET_DATABASE_URL: "not a url",
      }),
    ).toThrow(/SIGNET_DATABASE_URL/);
  });

  it("still requires a serving connection at all", () => {
    expect(() =>
      resolveMigrationIdentities({
        SIGNET_DATABASE_OWNER_URL: identities["SIGNET_DATABASE_OWNER_URL"],
      }),
    ).toThrow(/SIGNET_DATABASE_URL or SIGNET_DATABASE_HOST is required/);
  });

  it("puts no credential in any refusal", () => {
    // A role name is what an operator needs in order to act and is not a
    // credential. A password is neither, and this is a path whose messages reach
    // a Job's logs.
    const failures = [
      () =>
        resolveMigrationIdentities({
          ...identities,
          SIGNET_DATABASE_OWNER_URL: "postgres://db:5432/signet",
        }),
      () =>
        resolveMigrationIdentities({
          SIGNET_DATABASE_URL: "postgres://signet:p@db:5432/signet",
          SIGNET_DATABASE_OWNER_URL: "postgres://signet:owner-p@db:5432/signet",
        }),
      () =>
        resolveMigrationIdentities({
          ...identities,
          SIGNET_DATABASE_URL: "postgres://db:5432/signet",
        }),
    ];

    for (const failing of failures) {
      expect(failing).toThrow(ConfigError);
      let message = "";
      try {
        failing();
      } catch (error) {
        message = error instanceof Error ? error.message : String(error);
      }
      expect(message).not.toContain("owner-p");
      expect(message).not.toContain("postgres://");
    }
  });
});

describe("resolveSweepConfiguration", () => {
  // The sweep acts across tenants, so it needs the identity the policies exempt
  // and nothing else: no public URL, no master key, and not the serving
  // connection either, which it would delete nothing at all with.
  const OWNER_URL = "postgres://signet:owner-p@db:5432/signet";

  it("resolves the owner connection and the default grace period", () => {
    expect(
      resolveSweepConfiguration({ SIGNET_DATABASE_OWNER_URL: OWNER_URL }),
    ).toEqual({
      ownerUrl: OWNER_URL,
      // Twenty-four hours. An access token record is a revocation list entry, so
      // deleting one the moment it expires would answer a slightly late
      // introspection as an unknown token rather than an inactive one.
      accessTokenGraceMs: 24 * 60 * 60 * 1000,
    });
  });

  it("needs no other configuration", () => {
    // Not even SIGNET_DATABASE_URL. An operator running a maintenance job should
    // not be told off by name for omitting a variable the command never reads.
    expect(() =>
      resolveSweepConfiguration({ SIGNET_DATABASE_OWNER_URL: OWNER_URL }),
    ).not.toThrow();
  });

  it("requires the owning identity", () => {
    expect(() => resolveSweepConfiguration({})).toThrow(
      /SIGNET_DATABASE_OWNER_URL/,
    );
    expect(() => resolveSweepConfiguration({})).toThrow(ConfigError);
  });

  it.each([
    ["45s", 45_000],
    ["30m", 1_800_000],
    ["2h", 7_200_000],
    ["7d", 604_800_000],
    ["0h", 0],
  ])("reads a grace period of %s", (value, expected) => {
    expect(
      resolveSweepConfiguration({
        SIGNET_DATABASE_OWNER_URL: OWNER_URL,
        SIGNET_SWEEP_ACCESS_TOKEN_GRACE: value,
      }).accessTokenGraceMs,
    ).toBe(expected);
  });

  it.each(["24", "1 h", "an hour", "-1h", "24H", "1.5h", ""])(
    "rejects %p as a grace period",
    (value) => {
      // A unit is mandatory rather than assumed. A bare `24` read as seconds when
      // an operator meant hours is a sweep that deletes a live token's record,
      // and the failure mode of a misspelling should not be a silent one.
      const failing = (): unknown =>
        resolveSweepConfiguration({
          SIGNET_DATABASE_OWNER_URL: OWNER_URL,
          SIGNET_SWEEP_ACCESS_TOKEN_GRACE: value,
        });

      if (value === "") {
        // A blank string is an unset variable everywhere else in this module, so
        // it takes the default rather than failing.
        expect(failing).not.toThrow();
        return;
      }
      expect(failing).toThrow(/SIGNET_SWEEP_ACCESS_TOKEN_GRACE/);
    },
  );

  it("refuses a grace period longer than a century", () => {
    // Not pedantry: a cut-off of `now - 999999999d` is not a Date at all, and
    // without this the command logs the identity it verified, sweeps three tables
    // and then dies on a RangeError with a stack trace. A configuration that
    // cannot work should be refused by name before anything is deleted.
    expect(() =>
      resolveSweepConfiguration({
        SIGNET_DATABASE_OWNER_URL: OWNER_URL,
        SIGNET_SWEEP_ACCESS_TOKEN_GRACE: "999999999d",
      }),
    ).toThrow(/SIGNET_SWEEP_ACCESS_TOKEN_GRACE/);
  });

  it("accepts the longest grace period anybody would write", () => {
    // The ceiling is high enough to be irrelevant to a real deployment: whatever
    // an operator's clock skew is, it is not decades.
    expect(
      resolveSweepConfiguration({
        SIGNET_DATABASE_OWNER_URL: OWNER_URL,
        SIGNET_SWEEP_ACCESS_TOKEN_GRACE: "3650d",
      }).accessTokenGraceMs,
    ).toBe(3650 * 86_400_000);
  });

  it("puts no credential in a refusal", () => {
    let message = "";
    try {
      resolveSweepConfiguration({
        SIGNET_DATABASE_OWNER_URL: OWNER_URL,
        SIGNET_SWEEP_ACCESS_TOKEN_GRACE: "forever",
      });
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message).not.toContain("owner-p");
    expect(message).not.toContain("postgres://");
  });
});

describe("loadConfig - log level", () => {
  it.each(["debug", "info", "warn", "error"])("accepts %s", (level) => {
    expect(loadConfig(env({ SIGNET_LOG_LEVEL: level })).logLevel).toBe(level);
  });

  it("rejects an unknown level", () => {
    expect(() => loadConfig(env({ SIGNET_LOG_LEVEL: "verbose" }))).toThrow(
      /must be one of/,
    );
  });
});
