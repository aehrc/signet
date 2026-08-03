/**
 * Structural invariants of the schema, checked without a database.
 *
 * These are not tests of Drizzle. They are tests of the properties a later
 * change could quietly break: a plaintext credential column, an unindexed
 * foreign key, an accidental `ON DELETE NO ACTION`, or an enum drifting away
 * from the union in `@signet/core` that it is meant to mirror.
 */

import { is } from "drizzle-orm";
import { getTableConfig, PgTable } from "drizzle-orm/pg-core";
import { describe, expect, it } from "vitest";

import {
  auditActorTypeEnum,
  clientRequestStatusEnum,
  clientStatusEnum,
  clientTypeEnum,
  endpointAuthModeEnum,
  endpointConsentModeEnum,
  endpointKeyAlgorithmEnum,
  endpointKeyStatusEnum,
  endpointStatusEnum,
  grantTypeEnum,
  tenantMemberRoleEnum,
} from "./enums.js";
import * as schema from "./index.js";

import type { ClientType, GrantType } from "@signet/core";
import type { PgColumn } from "drizzle-orm/pg-core";

/** True only when two types are mutually assignable. */
type Exact<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;

/** Every table the data model is required to define. */
const EXPECTED_TABLES = [
  "access_tokens",
  "admin_sessions",
  "admin_users",
  "api_tokens",
  "audit_events",
  "authorization_codes",
  "authorization_sessions",
  "client_policy_overrides",
  "client_requests",
  "clients",
  "consents",
  "end_user_sessions",
  "end_users",
  "endpoint_keys",
  "endpoints",
  "federation_states",
  "idp_configs",
  "jti_replay",
  "launch_contexts",
  "policies",
  "refresh_tokens",
  "tenant_members",
  "tenants",
] as const;

const exported: readonly unknown[] = Object.values(schema);

const tables = exported
  .filter((value): value is PgTable => is(value, PgTable))
  .map((value) => getTableConfig(value));

/** Locates a table's configuration by its SQL name. */
function table(name: string): (typeof tables)[number] {
  const found = tables.find((candidate) => candidate.name === name);
  if (found === undefined) {
    throw new Error(`no table named ${name} is exported from the schema`);
  }
  return found;
}

/** The name of an indexed column, or a placeholder for an expression member. */
function columnName(member: unknown): string {
  if (typeof member === "object" && member !== null && "name" in member) {
    return String((member as { readonly name: unknown }).name);
  }
  return "«expression»";
}

/** Column-name tuples of every index on a table, in declaration order. */
function indexColumnNames(
  config: (typeof tables)[number],
): readonly (readonly string[])[] {
  return config.indexes.map((entry) => entry.config.columns.map(columnName));
}

/** Column-name tuples of only the unique indexes on a table. */
function uniqueIndexColumnNames(
  config: (typeof tables)[number],
): readonly (readonly string[])[] {
  return config.indexes
    .filter((entry) => entry.config.unique)
    .map((entry) => entry.config.columns.map(columnName));
}

/**
 * Whether a column can be found by an index scan: either it leads an index, or
 * it leads the primary key, or it is the primary key.
 */
function isIndexed(config: (typeof tables)[number], column: string): boolean {
  if (indexColumnNames(config).some((columns) => columns[0] === column)) {
    return true;
  }
  if (config.primaryKeys.some((key) => key.columns[0]?.name === column)) {
    return true;
  }
  return config.columns.some((c) => c.name === column && c.primary);
}

/** The `ON DELETE` action declared for the foreign key on a given column. */
function onDeleteFor(name: string, column: string): string | undefined {
  const key = table(name).foreignKeys.find((candidate) =>
    candidate.reference().columns.some((c) => c.name === column),
  );
  return key?.onDelete;
}

describe("schema completeness", () => {
  it("exports every table the data model requires", () => {
    const names = tables.map((config) => config.name).toSorted();
    expect(names).toEqual([...EXPECTED_TABLES].toSorted());
  });

  it("gives every table a distinct name in the public schema", () => {
    const names = tables.map((config) => config.name);
    expect(new Set(names).size).toBe(names.length);
    expect(tables.every((config) => config.schema === undefined)).toBe(true);
  });

  it("names every table and column in snake case", () => {
    const snakeCase = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/;
    const offenders = tables.flatMap((config) => [
      ...(snakeCase.test(config.name) ? [] : [config.name]),
      ...config.columns
        .filter((column) => !snakeCase.test(column.name))
        .map((column) => `${config.name}.${column.name}`),
    ]);
    expect(offenders).toEqual([]);
  });
});

describe("credential storage", () => {
  /**
   * Column name fragments that imply the value is a secret. Any such column has
   * to declare, in its own name, that it is either one-way hashed or encrypted
   * at rest — so a future `password` or `client_secret` column fails here rather
   * than shipping.
   */
  const SECRET_FRAGMENTS = ["password", "secret", "private"];

  /**
   * Column types capable of holding a secret at all. A timestamp such as
   * `secret_expires_at` names a secret without containing one, and exempting by
   * type rather than by an allowlist of names keeps the guard from being
   * loosened one name at a time.
   */
  const SECRET_CAPABLE_TYPES = new Set([
    "PgText",
    "PgVarchar",
    "PgChar",
    "PgJson",
    "PgJsonb",
    "PgBinary",
    "PgCustomColumn",
  ]);

  it("stores no column whose name implies a plaintext secret", () => {
    const offenders: string[] = [];
    for (const config of tables) {
      for (const column of config.columns) {
        const implied =
          SECRET_CAPABLE_TYPES.has(column.columnType) &&
          SECRET_FRAGMENTS.some((fragment) => column.name.includes(fragment));
        const protected_ =
          column.name.endsWith("_hash") || column.name.endsWith("_encrypted");
        if (implied && !protected_) {
          offenders.push(`${config.name}.${column.name}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  /**
   * Bearer credentials Signet accepts from a caller. Each must be stored as a
   * digest, and the table must carry no column that could hold the credential
   * itself.
   */
  const BEARER_CREDENTIALS: readonly {
    readonly table: string;
    readonly hashColumn: string;
    readonly forbidden: readonly string[];
  }[] = [
    {
      table: "api_tokens",
      hashColumn: "token_hash",
      forbidden: ["token", "secret"],
    },
    {
      table: "admin_sessions",
      hashColumn: "token_hash",
      forbidden: ["token", "session_token"],
    },
    {
      table: "authorization_codes",
      hashColumn: "code_hash",
      forbidden: ["code"],
    },
    {
      table: "refresh_tokens",
      hashColumn: "token_hash",
      forbidden: ["token", "refresh_token"],
    },
    {
      table: "launch_contexts",
      hashColumn: "handle_hash",
      forbidden: ["handle", "launch"],
    },
    {
      table: "admin_users",
      hashColumn: "password_hash",
      forbidden: ["password"],
    },
    {
      table: "end_users",
      hashColumn: "password_hash",
      forbidden: ["password"],
    },
    { table: "clients", hashColumn: "secret_hash", forbidden: ["secret"] },
  ];

  it.each(BEARER_CREDENTIALS)(
    "stores $table.$hashColumn hashed and nothing in clear",
    ({ table: name, hashColumn, forbidden }) => {
      const config = table(name);
      const columnNames = config.columns.map((column) => column.name);
      expect(columnNames).toContain(hashColumn);
      for (const forbiddenName of forbidden) {
        expect(columnNames).not.toContain(forbiddenName);
      }
    },
  );

  it("indexes every credential digest it looks rows up by", () => {
    // A password hash is only ever compared, never searched for; the token
    // digests are the lookup key of their table and must be unique.
    const lookupDigests = BEARER_CREDENTIALS.filter(
      ({ hashColumn }) =>
        hashColumn !== "password_hash" && hashColumn !== "secret_hash",
    );
    const offenders = lookupDigests
      .filter(
        ({ table: name, hashColumn }) =>
          !uniqueIndexColumnNames(table(name)).some(
            (columns) => columns.length === 1 && columns[0] === hashColumn,
          ),
      )
      .map(({ table: name, hashColumn }) => `${name}.${hashColumn}`);
    expect(offenders).toEqual([]);
  });

  it("encrypts, rather than hashes, the secrets Signet must present onward", () => {
    // A signing key and an upstream client secret have to be recoverable, so
    // these are the only values held in a reversible form.
    expect(
      table("endpoint_keys").columns.map((column) => column.name),
    ).toContain("private_jwk_encrypted");
    expect(table("idp_configs").columns.map((column) => column.name)).toContain(
      "client_secret_encrypted",
    );
    expect(table("admin_users").columns.map((column) => column.name)).toContain(
      "totp_secret_encrypted",
    );
  });
});

describe("indexing", () => {
  it("indexes every foreign key column", () => {
    const offenders: string[] = [];
    for (const config of tables) {
      for (const key of config.foreignKeys) {
        const columns: readonly PgColumn[] = key.reference().columns;
        const lead = columns[0];
        if (lead !== undefined && !isIndexed(config, lead.name)) {
          offenders.push(`${config.name}.${lead.name}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("indexes every expiry column so the sweep is not a full scan", () => {
    const offenders: string[] = [];
    for (const config of tables) {
      for (const column of config.columns) {
        if (column.name === "expires_at" && !isIndexed(config, column.name)) {
          offenders.push(`${config.name}.${column.name}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("indexes the jti primary lookup", () => {
    const accessTokens = table("access_tokens");
    expect(
      accessTokens.columns.find((column) => column.name === "jti")?.primary,
    ).toBe(true);
  });
});

describe("deletion behaviour", () => {
  it("declares an explicit ON DELETE action for every foreign key", () => {
    const offenders: string[] = [];
    for (const config of tables) {
      for (const key of config.foreignKeys) {
        if (key.onDelete === undefined) {
          const columns = key
            .reference()
            .columns.map((column) => column.name)
            .join(",");
          offenders.push(`${config.name}(${columns})`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("cascades a tenant deletion into its endpoints and their children", () => {
    const cascadesToEndpoint = [
      "clients",
      "client_requests",
      "end_user_sessions",
      "end_users",
      "endpoint_keys",
      "idp_configs",
      "policies",
      "access_tokens",
      "refresh_tokens",
      "authorization_sessions",
      "consents",
      "launch_contexts",
    ];
    expect(
      Object.fromEntries(
        cascadesToEndpoint.map((name) => [
          name,
          onDeleteFor(name, "endpoint_id"),
        ]),
      ),
    ).toEqual(
      Object.fromEntries(cascadesToEndpoint.map((name) => [name, "cascade"])),
    );
    expect(onDeleteFor("endpoints", "tenant_id")).toBe("cascade");
  });

  it("never lets an admin user deletion take history with it", () => {
    // Rows recording *what a person did* null their reference; rows that only
    // exist to serve that person (memberships, sessions) go with them.
    const nullsOnAdminDelete = [
      ["api_tokens", "created_by"],
      ["clients", "created_by"],
      ["policies", "created_by"],
      ["client_requests", "reviewer_id"],
    ] as const;
    expect(
      Object.fromEntries(
        nullsOnAdminDelete.map(([name, column]) => [
          `${name}.${column}`,
          onDeleteFor(name, column),
        ]),
      ),
    ).toEqual(
      Object.fromEntries(
        nullsOnAdminDelete.map(([name, column]) => [
          `${name}.${column}`,
          "set null",
        ]),
      ),
    );
  });

  it("keeps audit events free of any foreign key to a principal", () => {
    // `actor_id` is text on purpose: an audit trail a DELETE could orphan or
    // truncate would not be an audit trail.
    const audit = table("audit_events");
    const referenced = audit.foreignKeys.flatMap((key) =>
      key.reference().columns.map((column) => column.name),
    );
    expect(referenced).not.toContain("actor_id");
    expect(
      audit.columns.find((column) => column.name === "actor_id")?.columnType,
    ).toBe("PgText");
    const endpointKey = audit.foreignKeys.find((key) =>
      key.reference().columns.some((column) => column.name === "endpoint_id"),
    );
    expect(endpointKey?.onDelete).toBe("set null");
  });
});

describe("enums", () => {
  it("mirrors the ClientType union in @signet/core", () => {
    const matches: Exact<
      (typeof clientTypeEnum.enumValues)[number],
      ClientType
    > = true;
    expect(matches).toBe(true);
    expect([...clientTypeEnum.enumValues]).toEqual([
      "public",
      "confidential-symmetric",
      "confidential-asymmetric",
    ]);
  });

  it("mirrors the GrantType union in @signet/core", () => {
    const matches: Exact<(typeof grantTypeEnum.enumValues)[number], GrantType> =
      true;
    expect(matches).toBe(true);
    expect([...grantTypeEnum.enumValues]).toEqual([
      "authorization_code",
      "client_credentials",
      "refresh_token",
    ]);
  });

  it("fixes the remaining closed value sets", () => {
    expect([...tenantMemberRoleEnum.enumValues]).toEqual([
      "owner",
      "admin",
      "developer",
      "viewer",
    ]);
    expect([...endpointAuthModeEnum.enumValues]).toEqual([
      "local",
      "persona",
      "oidc",
    ]);
    expect([...endpointConsentModeEnum.enumValues]).toEqual([
      "always",
      "remember",
      "auto",
    ]);
    expect([...endpointStatusEnum.enumValues]).toEqual(["active", "disabled"]);
    expect([...endpointKeyAlgorithmEnum.enumValues]).toEqual([
      "RS384",
      "ES384",
    ]);
    expect([...endpointKeyStatusEnum.enumValues]).toEqual([
      "active",
      "next",
      "retired",
    ]);
    expect([...clientStatusEnum.enumValues]).toEqual([
      "pending",
      "active",
      "suspended",
      "rejected",
    ]);
    expect([...clientRequestStatusEnum.enumValues]).toEqual([
      "pending",
      "approved",
      "rejected",
    ]);
    expect([...auditActorTypeEnum.enumValues]).toEqual([
      "admin_user",
      "api_token",
      "end_user",
      "client",
      "system",
    ]);
  });

  it("uses a database enum, not free text, for every closed set", () => {
    const enumColumns = [
      ["tenant_members", "role"],
      ["api_tokens", "role"],
      ["endpoints", "auth_mode"],
      ["endpoints", "consent_mode"],
      ["endpoints", "status"],
      ["endpoint_keys", "algorithm"],
      ["endpoint_keys", "status"],
      ["clients", "client_type"],
      ["clients", "status"],
      ["client_requests", "status"],
      ["audit_events", "actor_type"],
    ] as const;
    const offenders = enumColumns
      .filter(([name, column]) => {
        const found = table(name).columns.find(
          (candidate) => candidate.name === column,
        );
        return (found?.enumValues?.length ?? 0) < 2;
      })
      .map(([name, column]) => `${name}.${column}`);
    expect(offenders).toEqual([]);
  });
});

describe("policy versioning", () => {
  it("permits at most one published policy version per endpoint", () => {
    const config = table("policies");
    const partial = config.indexes.find(
      (entry) => entry.config.name === "policies_one_published_per_endpoint",
    );
    expect(partial?.config.unique).toBe(true);
    expect(partial?.config.where).toBeDefined();
    expect(partial?.config.columns.map(columnName)).toEqual(["endpoint_id"]);
  });

  it("permits one row per (endpoint, version) and no more", () => {
    expect(uniqueIndexColumnNames(table("policies"))).toContainEqual([
      "endpoint_id",
      "version",
    ]);
  });
});

describe("replay prevention", () => {
  it("makes (client_id, jti) the primary key of the replay ledger", () => {
    const config = table("jti_replay");
    expect(
      config.primaryKeys.map((key) => key.columns.map((column) => column.name)),
    ).toEqual([["client_id", "jti"]]);
  });

  it("makes an authorization code single-use and uniquely addressable", () => {
    const config = table("authorization_codes");
    const columnNames = config.columns.map((column) => column.name);
    expect(columnNames).toContain("consumed_at");
    expect(columnNames).toContain("expires_at");
  });

  it("gives a launch handle a consumption marker", () => {
    expect(
      table("launch_contexts").columns.map((column) => column.name),
    ).toContain("consumed_at");
  });

  it("groups refresh tokens into a rotation family", () => {
    const columnNames = table("refresh_tokens").columns.map(
      (column) => column.name,
    );
    expect(columnNames).toContain("family_id");
    expect(columnNames).toContain("replaced_by_id");
    expect(isIndexed(table("refresh_tokens"), "family_id")).toBe(true);
  });
});

describe("endpoint capability configuration", () => {
  it("holds every EndpointCapabilityConfig flag as its own boolean column", () => {
    // Discrete columns, not JSONB: a missing key would read as `false` and
    // silently withdraw a capability the discovery document still advertises.
    const flags = [
      "supports_ehr_launch",
      "supports_standalone_launch",
      "supports_authorize_post",
      "allows_public_clients",
      "allows_confidential_symmetric_clients",
      "allows_confidential_asymmetric_clients",
      "supports_openid_connect",
      "supports_patient_banner",
      "supports_styling",
      "supports_ehr_patient_context",
      "supports_ehr_encounter_context",
      "supports_standalone_patient_context",
      "supports_standalone_encounter_context",
      "supports_offline_access",
      "supports_online_access",
      "supports_patient_scopes",
      "supports_user_scopes",
      "supports_v1_scopes",
      "supports_v2_scopes",
      "supports_backend_services",
      "supports_dynamic_registration",
    ];
    const config = table("endpoints");
    const shapes = Object.fromEntries(
      flags.map((flag) => {
        const column = config.columns.find(
          (candidate) => candidate.name === flag,
        );
        return [
          flag,
          {
            columnType: column?.columnType,
            notNull: column?.notNull,
            hasDefault: column?.hasDefault,
          },
        ];
      }),
    );
    expect(shapes).toEqual(
      Object.fromEntries(
        flags.map((flag) => [
          flag,
          { columnType: "PgBoolean", notNull: true, hasDefault: true },
        ]),
      ),
    );
  });

  it("defaults an endpoint to production, so personas are opt-in", () => {
    const column = table("endpoints").columns.find(
      (candidate) => candidate.name === "is_production",
    );
    expect(column?.notNull).toBe(true);
    expect(column?.default).toBe(true);
  });
});
