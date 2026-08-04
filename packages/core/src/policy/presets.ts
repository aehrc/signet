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
 * Translates SMART scopes into Pathling's `authorities` claim.
 *
 * Pathling does not read SMART scopes. It authorises off a Spring Security style
 * `authorities` claim, whose grammar is:
 *
 *   - `pathling:read:{ResourceType}` / `pathling:write:{ResourceType}`, or the
 *     bare `pathling:read` / `pathling:write` for every type;
 *   - operation authorities `pathling:search`, `pathling:import`,
 *     `pathling:import-pnp`, `pathling:update`, `pathling:delete`,
 *     `pathling:batch`, `pathling:bulk-submit`, `pathling:export`,
 *     `pathling:view-run`, `pathling:view-export`.
 *
 * The rule that makes this non-obvious: an operation authority is required *in
 * addition to* a read or write authority. `pathling:search` alone does not
 * permit searching, so every rule that emits an operation authority is paired
 * with the rule that emits the corresponding data authority, and the pairing is
 * asserted exhaustively in the tests.
 *
 * The mapping is deliberately narrow. Reads and searches follow from `r` and
 * `s`; bulk export follows from a system-context read, since `$export` is a
 * whole-population read; creates and updates map to `pathling:update` (Pathling
 * has no separate create authority) and deletes to `pathling:delete`. The
 * administrative operations - import, batch, bulk submit and the SQL-on-FHIR view
 * operations - have no SMART scope that implies them and are never granted
 * implicitly. An operator who wants them adds a rule, as the disabled import
 * rule below illustrates.
 *
 * `s` also yields a read authority: a Pathling search returns the resources it
 * matched, so search without read would be an authority set that cannot serve a
 * single request.
 */
export const PATHLING_PRESET: PolicyDocument = {
  version: 1,
  scopeGrants: [
    ...SMART_READ_GRANTS,
    {
      id: "grant-system-write",
      description:
        "Enable this to let a backend service write to the data warehouse.",
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
      id: "pathling-export",
      description:
        "Bulk export is a whole-population read, so it follows from a system-context read.",
      forEachScope: "system/*.r",
      appendTo: "authorities",
      values: ["pathling:export"],
    },
    {
      id: "pathling-write",
      description: "Data authority for creates, updates and deletes.",
      forEachScope: "*/*.cud",
      appendTo: "authorities",
      values: ["pathling:write{{ scope.resourceTypeSuffix }}"],
    },
    {
      id: "pathling-update",
      description:
        "Operation authority covering both create and update; Pathling has no separate create.",
      forEachScope: "*/*.cu",
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
      id: "pathling-import",
      description:
        "Bulk import is administrative and is never implied by a SMART scope. Enable it deliberately.",
      enabled: false,
      forEachScope: "system/*.c",
      appendTo: "authorities",
      values: ["pathling:import"],
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
    description:
      "Translates SMART scopes into Pathling's authorities claim, pairing each operation authority with the data authority it needs.",
    policy: PATHLING_PRESET,
    references: [
      {
        label: "Pathling - Authorization",
        url: "https://pathling.csiro.au/docs/server/authorization",
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
];
