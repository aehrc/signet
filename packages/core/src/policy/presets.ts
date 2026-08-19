/**
 * Author: John Grimes
 */

import type {
  ClaimRule,
  ContextRule,
  PolicyDocument,
  ScopeGrantRule,
} from "./types.js";

/** One hour, the SMART-conventional access token lifetime. */
const ACCESS_TOKEN_TTL = 3600;

/** Thirty days, long enough for a patient-facing app to stay connected. */
const REFRESH_TOKEN_TTL = 2_592_000;

/**
 * The read grants both presets start from.
 *
 * Deny-by-default does the rest: nothing here grants a write, so an operator
 * enables writing by adding a rule rather than by remembering to remove one. The
 * failure mode of a forgotten edit is then a rejected request, not an unintended
 * write to a clinical record.
 *
 * Patient-context scopes require a patient in the launch context, because
 * granting `patient/Observation.rs` with no patient resolved would hand the app a
 * token whose meaning depends on whatever the FHIR server infers.
 */
const SMART_READ_GRANTS: readonly ScopeGrantRule[] = [
  {
    id: "grant-patient-read",
    description: "Patient-context reads, once a patient has been resolved.",
    match: "patient/*.rs",
    allow: true,
    narrow: true,
    requireContext: ["patient"],
  },
  {
    id: "grant-user-read",
    description: "Reads across everything the signed-in user may see.",
    match: "user/*.rs",
    allow: true,
    narrow: true,
  },
  {
    id: "grant-system-read",
    description: "Backend service reads, for client credentials only.",
    match: "system/*.rs",
    allow: true,
    narrow: true,
    grantTypes: ["client_credentials"],
  },
];

/**
 * The identity, launch and refresh grants an app needs to run a session.
 *
 * These are all non-resource scopes, matched by exact equality rather than by a
 * pattern, which is the only way a policy can speak about them.
 */
const SMART_SESSION_GRANTS: readonly ScopeGrantRule[] = [
  { id: "grant-openid", match: "openid", allow: true },
  { id: "grant-fhir-user", match: "fhirUser", allow: true },
  { id: "grant-launch", match: "launch", allow: true },
  { id: "grant-launch-patient", match: "launch/patient", allow: true },
  { id: "grant-launch-encounter", match: "launch/encounter", allow: true },
  {
    id: "grant-offline-access",
    description: "Refresh tokens, for confidential clients only.",
    match: "offline_access",
    allow: true,
    clientTypes: ["confidential-symmetric", "confidential-asymmetric"],
  },
];

/** Identifies the signed-in user, dropped when there is no user or no record. */
const FHIR_USER_CLAIM_RULES: readonly ClaimRule[] = [
  {
    id: "claim-fhir-user",
    description: "Identifies the signed-in user as a FHIR resource.",
    when: { hasUser: true },
    emit: { fhirUser: "{{ user.fhirUser }}" },
  },
];

/**
 * Context rules every preset shares.
 *
 * `need_patient_banner` is emitted twice on purpose: a launch that carries a
 * patient gets the conservative default of `true`, and the EHR's own value then
 * overwrites it when one was supplied. Because an unresolvable template drops
 * the claim instead of emitting null, the default survives when the EHR said
 * nothing.
 */
const SMART_CONTEXT_RULES: readonly ContextRule[] = [
  {
    id: "context-patient",
    description: "Passes the patient in context to the app.",
    when: { context: ["patient"] },
    emit: { patient: "{{ context.patient }}" },
  },
  {
    id: "context-encounter",
    description: "Passes the encounter in context to the app.",
    when: { context: ["encounter"] },
    emit: { encounter: "{{ context.encounter }}" },
  },
  {
    id: "context-need-patient-banner-default",
    description:
      "Assumes a banner is needed whenever a patient is in context, unless the launch says otherwise.",
    when: { context: ["patient"] },
    emit: { need_patient_banner: true },
  },
  {
    id: "context-need-patient-banner",
    description: "Honours the banner requirement stated by the launch.",
    when: { context: ["needPatientBanner"] },
    emit: { need_patient_banner: "{{ context.needPatientBanner }}" },
  },
  {
    id: "context-smart-style-url",
    description: "Passes the EHR's style sheet URL to the app.",
    when: { context: ["smartStyleUrl"] },
    emit: { smart_style_url: "{{ context.smartStyleUrl }}" },
  },
  {
    id: "context-intent",
    when: { context: ["intent"] },
    emit: { intent: "{{ context.intent }}" },
  },
  {
    id: "context-tenant",
    when: { context: ["tenant"] },
    emit: { tenant: "{{ context.tenant }}" },
  },
  {
    id: "context-fhir-context",
    when: { context: ["fhirContext"] },
    emit: { fhirContext: "{{ context.fhirContext }}" },
  },
];

/**
 * A conservative SMART App Launch starting point, for a FHIR server that reads
 * SMART scopes itself.
 *
 * Read-only, for the reasons given on {@link SMART_READ_GRANTS}. There are no
 * scope mappings: the token carries the granted scopes and a `fhirUser` claim,
 * and the server does its own interpreting.
 */
export const SMART_BASELINE_PRESET: PolicyDocument = {
  version: 1,
  scopeGrants: [
    ...SMART_READ_GRANTS,
    ...SMART_SESSION_GRANTS,
    { id: "grant-online-access", match: "online_access", allow: true },
  ],
  claimRules: FHIR_USER_CLAIM_RULES,
  contextRules: SMART_CONTEXT_RULES,
  defaults: {
    accessTokenTtl: ACCESS_TOKEN_TTL,
    refreshTokenTtl: REFRESH_TOKEN_TTL,
  },
};

/**
 * The role a user must hold before this preset will grant a write scope.
 *
 * Namespaced rather than a plain `admin`, so a deployment running several
 * resource servers behind one identity provider can hold a distinct
 * administrator role per server. An operator whose provider issues a different
 * name edits this one rule.
 */
const PATHLING_ADMIN_ROLE = "pathling-admin";

/**
 * Translates SMART scopes into Pathling's `authorities` claim.
 *
 * Written against Pathling `release/server/3.0.0`, and covering every authority
 * that release understands. Pathling does not read SMART scopes; it authorises
 * off a Spring Security style `authorities` claim, whose grammar is:
 *
 *   - data authorities `pathling:read:{ResourceType}` and
 *     `pathling:write:{ResourceType}`, or the bare `pathling:read` /
 *     `pathling:write` covering every type;
 *   - operation authorities `pathling:search`, `pathling:read-resource`,
 *     `pathling:create`, `pathling:update`, `pathling:delete`,
 *     `pathling:batch`, `pathling:import`, `pathling:import-pnp`,
 *     `pathling:bulk-submit`, `pathling:export`, `pathling:sql-run`,
 *     `pathling:sql-export` and `pathling:jobs`;
 *   - the bare `pathling`, which subsumes all of the above and which this preset
 *     never emits.
 *
 * The operation list is taken from the `@OperationAccess` annotations in the
 * server source as at `378dba82a9`, which the branch's own documentation table
 * now matches exactly.
 *
 * **3.0.0 is a prerequisite, not a preference.** Pathling's authority grammar only
 * admitted a hyphen in the action segment from November 2025, and an authority it
 * cannot parse raises rather than being ignored - so against an older server a
 * token carrying `pathling:sql-run` fails *every* request with a 500, including
 * the ones it was entitled to make. An operator on a released Pathling should
 * disable the five hyphenated rules below - read by id, SQL run and export,
 * ping-and-pull import, and bulk submit - until they upgrade.
 *
 * The rule that makes this non-obvious: an operation authority is required *in
 * addition to* a read or write authority. `pathling:search` alone does not
 * permit searching, so every rule that emits an operation authority is paired
 * with the rule that emits the corresponding data authority, and the pairing is
 * asserted exhaustively in the tests.
 *
 * **What follows from a read.** `r` and `s` both yield the data authority, since
 * a search returns the resources it matched and search without read is an
 * authority set that cannot serve a single request. `s` additionally yields
 * `pathling:search`. `r` yields the read-by-id operation (`read-resource`) and
 * the operations that read a population: export, and the SQL on FHIR run and
 * export operations. Each is still bounded by the data authority beside it, so a
 * typed scope cannot project a type it did not name. Note that these are not
 * narrowed by launch context, because a Pathling authority carries no patient
 * compartment: `pathling:read:Observation` already reads every Observation in the
 * warehouse whether it came from a patient-context scope or a system one.
 *
 * **What follows from a write.** `c`, `u` and `d` yield the data authority; `c`
 * yields `pathling:create`, `u` yields `pathling:update` and `d` yields
 * `pathling:delete`. 3.0.0 separates create from update, so unlike earlier
 * versions a create-only scope does not carry the authority to overwrite an
 * existing resource. Any write yields `pathling:batch`, which is the transport
 * for the same three interactions in a bundle. `c` also yields the bulk loading
 * operations - import, ping-and-pull import and bulk submit - each of which
 * remains bounded to the types named by the write authorities beside it.
 *
 * **Who can write at all.** Nobody, by default. The only rule naming a write is
 * `grant-admin-write`, which requires the user to hold {@link
 * PATHLING_ADMIN_ROLE}; a user without it who asks for `user/Patient.cruds` is
 * narrowed to `user/Patient.rs` rather than refused. The separate
 * `grant-system-write` covers an unattended data loader running as a backend
 * service, and ships disabled because a `client_credentials` grant has no user
 * and therefore no role to check.
 */
export const PATHLING_PRESET: PolicyDocument = {
  version: 1,
  scopeGrants: [
    {
      id: "grant-admin-write",
      description: `Full access for a user holding the ${PATHLING_ADMIN_ROLE} role. The only rule here that names a write.`,
      match: "user/*.cruds",
      allow: true,
      narrow: true,
      requireUserRole: [PATHLING_ADMIN_ROLE],
    },
    ...SMART_READ_GRANTS,
    {
      id: "grant-system-write",
      description:
        "Enable this to let an unattended backend service write to the data warehouse. Separate from the admin rule because a client credentials grant has no user, and so no role to check.",
      match: "system/*.cud",
      allow: true,
      enabled: false,
      grantTypes: ["client_credentials"],
    },
    ...SMART_SESSION_GRANTS,
  ],
  claimRules: FHIR_USER_CLAIM_RULES,
  scopeMappings: [
    {
      id: "pathling-read",
      description:
        "Data authority for reads. Search implies read, because a search returns resources.",
      forEachScope: "*/*.rs",
      appendTo: "authorities",
      values: ["pathling:read{{ scope.resourceTypeSuffix }}"],
    },
    {
      id: "pathling-search",
      description: "Operation authority for search, required on top of read.",
      forEachScope: "*/*.s",
      appendTo: "authorities",
      values: ["pathling:search"],
    },
    {
      id: "pathling-read-resource",
      description:
        "Operation authority for read by id, required on top of the data authority for the type being read. Named apart from the bare read data authority so a typed scope can fetch by id without being granted read across every type.",
      forEachScope: "*/*.r",
      appendTo: "authorities",
      values: ["pathling:read-resource"],
    },
    {
      id: "pathling-export",
      description:
        "Bulk export is a whole-population read, bounded by the read authorities beside it.",
      forEachScope: "*/*.r",
      appendTo: "authorities",
      values: ["pathling:export"],
    },
    {
      id: "pathling-sql-run",
      description:
        "Runs a ViewDefinition or SQL Library. Needs read on every projected type, and on ViewDefinition or Library when the subject is resolved from storage rather than supplied inline.",
      forEachScope: "*/*.r",
      appendTo: "authorities",
      values: ["pathling:sql-run"],
    },
    {
      id: "pathling-sql-export",
      description:
        "Exports the result of a ViewDefinition or SQL Library. Same read requirements as running one.",
      forEachScope: "*/*.r",
      appendTo: "authorities",
      values: ["pathling:sql-export"],
    },
    {
      id: "pathling-jobs",
      description:
        "Lists the caller's own asynchronous jobs. Follows from any resource access, because an export and an import can both start one.",
      forEachScope: "*/*.cruds",
      appendTo: "authorities",
      values: ["pathling:jobs"],
    },
    {
      id: "pathling-write",
      description: "Data authority for creates, updates and deletes.",
      forEachScope: "*/*.cud",
      appendTo: "authorities",
      values: ["pathling:write{{ scope.resourceTypeSuffix }}"],
    },
    {
      id: "pathling-create",
      description:
        "Operation authority for create. Separate from update since Pathling 3.0.0, so a create-only scope cannot overwrite an existing resource.",
      forEachScope: "*/*.c",
      appendTo: "authorities",
      values: ["pathling:create"],
    },
    {
      id: "pathling-update",
      description: "Operation authority for update.",
      forEachScope: "*/*.u",
      appendTo: "authorities",
      values: ["pathling:update"],
    },
    {
      id: "pathling-delete",
      description: "Operation authority for delete.",
      forEachScope: "*/*.d",
      appendTo: "authorities",
      values: ["pathling:delete"],
    },
    {
      id: "pathling-batch",
      description:
        "Operation authority for a batch bundle, the transport for the same three interactions.",
      forEachScope: "*/*.cud",
      appendTo: "authorities",
      values: ["pathling:batch"],
    },
    {
      id: "pathling-import",
      description:
        "Bulk import, bounded to the types named by the write authorities beside it.",
      forEachScope: "*/*.c",
      appendTo: "authorities",
      values: ["pathling:import"],
    },
    {
      id: "pathling-import-pnp",
      description: "Ping and pull import, which loads from a Bulk Data server.",
      forEachScope: "*/*.c",
      appendTo: "authorities",
      values: ["pathling:import-pnp"],
    },
    {
      id: "pathling-bulk-submit",
      description:
        "Submits a bulk export to another server and ingests the result.",
      forEachScope: "*/*.c",
      appendTo: "authorities",
      values: ["pathling:bulk-submit"],
    },
  ],
  contextRules: SMART_CONTEXT_RULES,
  defaults: {
    accessTokenTtl: ACCESS_TOKEN_TTL,
    refreshTokenTtl: REFRESH_TOKEN_TTL,
  },
};

/**
 * Emits the patient compartment as a claim *inside* the access token.
 *
 * SMART puts `patient` in the token response body, not in the token, and a server
 * that authorises off the JWT alone never sees it there. Three of the resource
 * servers below therefore need it as a claim as well - which is the whole content
 * of their presets, and the reason those presets are worth shipping rather than
 * telling an operator to start from the baseline.
 *
 * Gated on a resolved patient, so a user-context or backend authorization emits no
 * `patient` claim at all rather than an empty one. A server matching a compartment
 * against `""` is a server granting more than was asked for.
 *
 * @param description - What the vendor does with the claim, for the rule's label.
 */
function patientClaimRule(description: string): ClaimRule {
  return {
    id: "claim-patient",
    description,
    when: { context: ["patient"] },
    emit: { patient: "{{ context.patient }}" },
  };
}

/**
 * The baseline plus the patient claim, for a server that reads the token itself.
 *
 * A factory rather than two near-identical documents, because Firely Server and
 * Smile CDR want the same thing and the honest way to say so is to build both from
 * one expression. What differs between them is the citation and the wording of the
 * rule, not the policy.
 *
 * @param claimDescription - What the vendor does with the `patient` claim.
 */
function tokenPatientPreset(claimDescription: string): PolicyDocument {
  return {
    ...SMART_BASELINE_PRESET,
    claimRules: [...FHIR_USER_CLAIM_RULES, patientClaimRule(claimDescription)],
  };
}

/**
 * Aidbox reads SMART v2 scopes, but wants the patient nested and the token
 * versioned.
 *
 * Two things distinguish it from the baseline, and both are documented. `atv: 2`
 * declares the access token to be SMART v2 rather than v1, and Aidbox refuses to
 * apply v2 scope semantics without it. The patient compartment is read from
 * `context.patient` - nested inside a `context` object rather than sitting at the
 * top level as it does everywhere else.
 *
 * The nesting is why `emit` takes arbitrary JSON rather than a flat record: the
 * templates inside a nested object are rendered, and a property whose template
 * cannot resolve is dropped, so `context` carries only what was actually resolved.
 */
export const AIDBOX_PRESET: PolicyDocument = {
  ...SMART_BASELINE_PRESET,
  claimRules: [
    ...FHIR_USER_CLAIM_RULES,
    {
      id: "claim-aidbox-token-version",
      description:
        "Declares a SMART v2 access token. Aidbox will not apply v2 scope semantics without it.",
      when: {},
      emit: { atv: 2 },
    },
    {
      id: "claim-aidbox-context",
      description:
        "Aidbox reads the patient compartment from context.patient, not from a top-level claim.",
      when: { context: ["patient"] },
      emit: { context: { patient: "{{ context.patient }}" } },
    },
  ],
};

/**
 * Firely Server: the baseline plus `patient`, and an audience that has to match.
 *
 * Firely enforces compartments from the `patient` claim, resolving it through the
 * configured `PatientFilter` - `_id` by default, but an installation may match on
 * `identifier` instead, in which case what belongs in the claim is the patient's
 * business identifier rather than its resource id. Signet emits whatever the launch
 * context resolved, so an operator whose Firely is configured that way sets the
 * launch context accordingly; there is nothing this preset can decide for them.
 *
 * `aud` is mandatory and must equal Firely's configured audience. Signet always
 * sets it to the endpoint's FHIR base URL, so this is a configuration match rather
 * than a policy rule.
 */
export const FIRELY_PRESET: PolicyDocument = tokenPatientPreset(
  "Firely enforces the patient compartment from this claim, via its configured PatientFilter.",
);

/**
 * Smile CDR: the baseline plus `patient`, for the inbound-security login script.
 *
 * Smile CDR accepts an external authorization server's token, but what it does with
 * the claims is decided by an operator-authored login script in the SMART Inbound
 * Security module - so like HAPI, its contract is whatever that script reads. The
 * documented convention for a third-party server is to communicate the patient's
 * identity in a claim on the access token, which the script then decodes to assign
 * permissions. That convention is what this preset mints.
 */
export const SMILE_CDR_PRESET: PolicyDocument = tokenPatientPreset(
  "Smile CDR's inbound-security login script reads this claim to assign patient permissions.",
);

/**
 * The role a user must hold before this preset will grant a write scope.
 *
 * Namespaced like {@link PATHLING_ADMIN_ROLE}, and for the same reason: a
 * deployment running several resource servers behind one identity provider can
 * hold a distinct administrator role per server.
 */
const ONTOSERVER_ADMIN_ROLE = "ontoserver-admin";

/**
 * Translates SMART scopes into the authority strings Ontoserver enforces.
 *
 * Written against the Ontoserver 6 security model. Ontoserver does not read
 * SMART v2 scopes: it merges the token's `scope` and `authorities` claims into
 * one set and matches it, as literal strings, against the scopes its
 * documentation names - `system/*.read`, `system/*.write`,
 * `system/CodeSystem.x-upload-external`, and the `onto/api.*` and
 * `onto/synd.*` pairs for its non-FHIR endpoints. A granted `user/ValueSet.rs`
 * therefore has to become the exact string `system/*.read` inside the
 * `authorities` claim, which is what the mapping table here does.
 *
 * **The documented authorities are server-wide, and the mapping says so.**
 * There is no per-resource-type or per-compartment string in Ontoserver's
 * published contract, so a granted read scope of any shape yields
 * `system/*.read` and a granted write scope yields `system/*.write` - whole
 * server, whatever the scope named. That is why this preset grants no
 * `patient/` scopes, drops the `launch/patient` and `launch/encounter` session
 * scopes, and passes no patient, encounter or banner context parameters to the
 * app: a patient scope would hand the app server-wide read under a name that
 * promises less, and there is no patient for a launch to resolve. An operator
 * who needs finer write control uses
 * Ontoserver's own resource-level mechanism (`ontoserver.security.enabled=fine`
 * with security labels and `grouping/` scopes), whose categories are
 * deployment-specific and therefore not something a preset can mint.
 *
 * **What follows from a read.** `r` and `s` both yield `system/*.read`:
 * Ontoserver has no separate search permission, and a search returns the
 * resources it matched. The read authority also covers `$validate`, `$convert`,
 * `$expand` and `$closure`, so this preset mints nothing operation-specific for
 * them.
 *
 * **What follows from a write.** `c`, `u` and `d` yield `system/*.write`, and
 * nothing else: Ontoserver documents that a write permission does not convey
 * read.
 *
 * **Two authorities ship as disabled rules.**
 * `system/CodeSystem.x-upload-external` guards the endpoint that ingests an
 * external code system release (a SNOMED CT RF2 archive, for instance) and is
 * deliberately outside `system/*.write` on Ontoserver's side, so it is a
 * separate rule here, emitted only for a create scope that names CodeSystem -
 * an app must ask for CodeSystem creation by name to carry it.
 * `onto/synd.write` is required before Ontoserver will overwrite a resource
 * that arrived via syndication, and follows from update and delete scopes once
 * enabled.
 *
 * **Who can write at all.** Nobody, by default - the same posture as {@link
 * PATHLING_PRESET}, expressed by the same pair of rules: a user write grant
 * requiring {@link ONTOSERVER_ADMIN_ROLE}, and a disabled backend-service grant
 * for an unattended loader.
 *
 * **Key configuration is part of the contract.** Ontoserver verifies tokens
 * against a static key in `ontoserver.security.token.secret` - an RSA public
 * key in PEM form, or an HMAC secret - and never fetches a JWKS. Its decoder is
 * Spring Security's default, which accepts RS256 and nothing else for an RSA
 * key, so the endpoint's signing key must use RS256 and the operator pastes its
 * PEM public key into that property. When `ontoserver.security.audience` is set
 * it must equal the endpoint's FHIR base URL, which is what Signet puts in
 * `aud`.
 */
export const ONTOSERVER_PRESET: PolicyDocument = {
  version: 1,
  scopeGrants: [
    {
      id: "grant-admin-write",
      description: `Full access for a user holding the ${ONTOSERVER_ADMIN_ROLE} role. The only enabled rule here that names a write.`,
      match: "user/*.cruds",
      allow: true,
      narrow: true,
      requireUserRole: [ONTOSERVER_ADMIN_ROLE],
    },
    // No patient grant: a terminology server has no patient compartment, and an
    // Ontoserver authority could not express one anyway.
    ...SMART_READ_GRANTS.filter((rule) => rule.id !== "grant-patient-read"),
    {
      id: "grant-system-write",
      description:
        "Enable this to let an unattended backend service load terminology. Separate from the admin rule because a client credentials grant has no user, and so no role to check.",
      match: "system/*.cud",
      allow: true,
      enabled: false,
      grantTypes: ["client_credentials"],
    },
    // The patient and encounter launch-context scopes are dropped along with
    // the patient grant: there is nothing for them to resolve.
    ...SMART_SESSION_GRANTS.filter(
      (rule) =>
        rule.id !== "grant-launch-patient" &&
        rule.id !== "grant-launch-encounter",
    ),
  ],
  claimRules: FHIR_USER_CLAIM_RULES,
  scopeMappings: [
    {
      id: "ontoserver-read",
      description:
        "The documented read authority, which is server-wide. Search implies read, because Ontoserver has no separate search permission; read also covers $validate, $convert, $expand and $closure.",
      forEachScope: "*/*.rs",
      appendTo: "authorities",
      values: ["system/*.read"],
    },
    {
      id: "ontoserver-write",
      description:
        "The documented write authority, which is server-wide. Yields no read: Ontoserver documents that a write permission does not convey read.",
      forEachScope: "*/*.cud",
      appendTo: "authorities",
      values: ["system/*.write"],
    },
    {
      id: "ontoserver-upload-external",
      description:
        "Enable this to let a create scope naming CodeSystem upload an external code system release, such as a SNOMED CT RF2 archive. Ontoserver keeps this outside system/*.write on purpose, so it is a separate rule here.",
      forEachScope: "*/CodeSystem.c",
      appendTo: "authorities",
      values: ["system/CodeSystem.x-upload-external"],
      enabled: false,
    },
    {
      id: "ontoserver-synd-write",
      description:
        "Enable this to let update and delete scopes overwrite resources that arrived via syndication, which Ontoserver otherwise refuses.",
      forEachScope: "*/*.ud",
      appendTo: "authorities",
      values: ["onto/synd.write"],
      enabled: false,
    },
  ],
  // The patient-facing context parameters go with the patient grants: a
  // terminology server launch has no patient to pass and no banner to show.
  contextRules: SMART_CONTEXT_RULES.filter(
    (rule) =>
      rule.id !== "context-patient" &&
      rule.id !== "context-encounter" &&
      rule.id !== "context-need-patient-banner-default" &&
      rule.id !== "context-need-patient-banner",
  ),
  defaults: {
    accessTokenTtl: ACCESS_TOKEN_TTL,
    refreshTokenTtl: REFRESH_TOKEN_TTL,
  },
};

/** Where a preset's claim contract is documented. */
export interface PresetReference {
  readonly label: string;
  readonly url: string;
}

/** A named, selectable policy starting point. */
export interface PolicyPreset {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly policy: PolicyDocument;
  /**
   * The vendor documentation this preset was written from.
   *
   * Not decoration. A preset asserts what another system will do with a token, and
   * an operator has no way to check that assertion without the page it came from -
   * so every preset that speaks about a specific product carries its citation, and
   * a product whose contract could not be found gets no preset at all. The console
   * shows these beside the preset.
   */
  readonly references: readonly PresetReference[];
}

/**
 * Every preset an operator can start an endpoint from.
 *
 * Notably absent: **Medplum**, and it is absent for a reason rather than an
 * oversight. Medplum documents which SMART scopes it supports, but its FHIR API
 * authorises off tokens Medplum itself issued; its external-identity support
 * federates *login*, not authorization. There is no published contract for a
 * third-party access token, so there is nothing here to cite and no preset.
 *
 * **HAPI FHIR** is absent for a different reason: it has no claim contract at all,
 * because `AuthorizationInterceptor` requires the operator to write Java. The
 * baseline preset mints a clean standards JWT for it, and the useful half of that
 * pairing is the generated interceptor that consumes it - see
 * `integrations/hapiInterceptor.ts`.
 */
export const POLICY_PRESETS: readonly PolicyPreset[] = [
  {
    id: "smart-baseline",
    name: "SMART baseline",
    description:
      "Read-only SMART App Launch: patient, encounter and banner context, plus a fhirUser claim. A safe starting point for a server that reads SMART scopes itself, including HAPI FHIR behind a generated interceptor.",
    policy: SMART_BASELINE_PRESET,
    references: [
      {
        label: "SMART App Launch 2.2.0 - Scopes and Launch Context",
        url: "https://hl7.org/fhir/smart-app-launch/STU2.2/scopes-and-launch-context.html",
      },
    ],
  },
  {
    id: "pathling",
    name: "Pathling",
    description: `Translates SMART scopes into Pathling's authorities claim, pairing each operation authority with the data authority it needs. Covers every authority in Pathling 3.0.0. Reads are open to any user; writing requires the ${PATHLING_ADMIN_ROLE} role.`,
    policy: PATHLING_PRESET,
    references: [
      {
        label: "Pathling - Authorization",
        url: "https://pathling.csiro.au/docs/server/authorization",
      },
      {
        // The published documentation describes the released server rather
        // than 3.0.0, so the branch's annotations are the citable source for
        // the operation authorities this preset emits.
        label: "Pathling release/server/3.0.0 - OperationAccess annotations",
        url: "https://github.com/aehrc/pathling/tree/release/server/3.0.0/server/src/main/java/au/csiro/pathling",
      },
    ],
  },
  {
    id: "aidbox",
    name: "Aidbox",
    description:
      "SMART v2 scopes as Aidbox reads them: an atv claim declaring the token version, and the patient compartment nested under context.patient.",
    policy: AIDBOX_PRESET,
    references: [
      {
        label: "Aidbox - SMART: Scopes for Limiting Access",
        url: "https://docs.aidbox.app/access-control/authorization/smart-on-fhir/smart-scopes-for-limiting-access",
      },
    ],
  },
  {
    id: "firely",
    name: "Firely Server",
    description:
      "The baseline plus a patient claim inside the access token, which is where Firely reads the compartment from. Check that Firely's configured audience matches this endpoint's FHIR base URL.",
    policy: FIRELY_PRESET,
    references: [
      {
        label: "Firely Server - Tokens and Compartments",
        url: "https://docs.fire.ly/projects/Firely-Server/en/latest/security/tokens_and_compartments.html",
      },
    ],
  },
  {
    id: "smile-cdr",
    name: "Smile CDR",
    description:
      "The baseline plus a patient claim inside the access token, for the SMART Inbound Security login script to read. The script itself is the contract; this mints the documented convention it expects.",
    policy: SMILE_CDR_PRESET,
    references: [
      {
        label: "Smile CDR - SMART Inbound Security Module",
        url: "https://smilecdr.com/docs/smart/smart_on_fhir_inbound_security_module.html",
      },
    ],
  },
  {
    id: "ontoserver",
    name: "Ontoserver",
    description: `Translates SMART scopes into the v1-style authority strings Ontoserver matches inside the authorities claim. Reads are open to signed-in users and backend services; writing requires the ${ONTOSERVER_ADMIN_ROLE} role. The endpoint's signing key must use RS256, because Ontoserver verifies with a static PEM public key rather than a JWKS.`,
    policy: ONTOSERVER_PRESET,
    references: [
      {
        label: "Ontoserver - Security model",
        url: "https://ontoserver.csiro.au/docs/6/security-model.html",
      },
      {
        label: "Ontoserver - Security configuration",
        url: "https://ontoserver.csiro.au/docs/6/config-security.html",
      },
    ],
  },
];
