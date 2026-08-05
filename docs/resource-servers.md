# What each resource server wants in a token

Signet's presets assert what another system will do with an access token. That is a
claim about somebody else's software, so each one is written from that vendor's
documentation and carries the citation - visible beside the preset in the console.
A product whose contract could not be found in current documentation gets no
preset. There is nothing wrong with the escape hatch: the policy editor's
simulator shows the exact decoded token, so an undocumented server can be matched
by inspection in a few minutes.

Verified August 2026. If a vendor changes their contract, the preset is wrong until
somebody re-reads the page and fixes it - so the dates below are part of the
record, not decoration.

## SMART baseline

The only preset writable from a specification: the token claims and launch-context
response parameters that [SMART App Launch
2.2.0](https://hl7.org/fhir/smart-app-launch/STU2.2/scopes-and-launch-context.html)
mandates. Read-only, because deny-by-default means an operator enables writing by
adding a rule rather than by remembering to remove one.

## Pathling

[Pathling authorization](https://pathling.csiro.au/docs/server/authorization),
and the `@OperationAccess` annotations in the
[`release/server/3.0.0`](https://github.com/aehrc/pathling/tree/release/server/3.0.0)
server source, which the preset is written against. The source is cited as well as
the page because the page's authority table omits `create`, `sqlquery-run` and
`sqlquery-export`.

Pathling does not read SMART scopes. It authorises off a Spring Security style
`authorities` claim, and the rule that makes the mapping non-obvious is that an
operation authority is required _in addition to_ a read or write authority:
`pathling:search` alone does not permit searching. So `patient/Observation.rs`
becomes a `pathling:read:Observation` data authority followed by the operation
authorities its permissions imply.

Reads and searches both yield the data authority, because a Pathling search
returns the resources it matched. A read permission also yields the operations
that read a population rather than a single resource - export, the two
ViewDefinition operations and the two SQL query operations - each still bounded by
the data authority beside it, so a typed scope cannot project a type it did not
name. These are not narrowed by launch context, because a Pathling authority
carries no patient compartment: `pathling:read:Observation` already reads every
Observation in the warehouse, whether it came from a patient-context scope or a
system one. If a deployment needs the compartment enforced, that has to come from
Pathling's configuration, not from the token.

On the write side, 3.0.0 separates create from update, so a create-only scope
cannot overwrite an existing resource. Any write yields `pathling:batch`, and a
create additionally yields the bulk loading operations - import, ping-and-pull
import and bulk submit.

Nothing grants a write by default. The only rule that names one requires the user
to hold the `pathling-admin` role; a user without it who asks for
`user/Patient.cruds` is narrowed to `user/Patient.rs` rather than refused. A
separate rule, shipped disabled, covers an unattended data loader running as a
backend service, and is separate because a `client_credentials` grant has no user
and so no role to check.

One limitation is worth knowing before you debug it. Pathling's read-by-id
interaction demands the operation authority `pathling:read`, which is the same
string as the all-types read data authority, so `pathling:read:Observation` does
not satisfy it: a typed read scope can search a resource type but cannot fetch one
by id. Emitting the bare authority would grant read across every type and defeat
the narrowing, so the preset does not. The collision is reported upstream as
[aehrc/pathling#2702](https://github.com/aehrc/pathling/issues/2702), which
proposes renaming the operation authority to `pathling:read-resource`.

## Aidbox

[SMART: Scopes for Limiting
Access](https://docs.aidbox.app/access-control/authorization/smart-on-fhir/smart-scopes-for-limiting-access).

Aidbox reads SMART v2 scopes, and accepts tokens from an external issuer, with two
differences from the baseline:

- `atv: 2` declares the token to be SMART v2. Without it Aidbox does not apply v2
  scope semantics.
- The patient compartment is read from `context.patient` - nested inside a
  `context` object, not a top-level `patient` claim.

Aidbox then filters retrieved data by the FHIR Patient CompartmentDefinition, and
honours search parameters carried in a scope (`patient/Observation.rs?status=final`
filters to final observations).

## Firely Server

[Tokens and
compartments](https://docs.fire.ly/projects/Firely-Server/en/latest/security/tokens_and_compartments.html).

Mandatory `iss` and `aud`, where `aud` must equal Firely's configured
`SmartAuthorizationOptions.Audience`. Signet always sets `aud` to the endpoint's
FHIR base URL, so this is a configuration match rather than a policy rule - if
Firely rejects a Signet token, check that pair first.

The compartment comes from a `patient` claim _inside the token_, resolved through
Firely's configured `PatientFilter`. The default filter matches `_id`, but an
installation may match on `identifier` instead, in which case what belongs in the
claim is the patient's business identifier rather than its resource id. Signet
emits whatever the launch context resolved; no preset can decide that.

## Smile CDR

[SMART Inbound Security
module](https://smilecdr.com/docs/smart/smart_on_fhir_inbound_security_module.html).

Smile CDR accepts an external authorization server's token - an OpenID Connect
Server definition tells the inbound-security module to trust the issuer - but what
happens to the claims is decided by an operator-authored login script. Like HAPI,
the real contract is whatever that script reads. The documented convention for a
third-party server is to communicate the patient's identity in a claim on the
access token, which the script decodes to assign permissions, and that convention
is what the preset mints.

## HAPI FHIR (open source): no claim contract

`AuthorizationInterceptor` and `SearchNarrowingInterceptor` both require the
operator to write Java - `buildRuleList` and `buildAuthorizedList` respectively -
and neither reads a token on its own. There is no contract to write a preset
against.

So the useful deliverable is the other half of the handshake: Signet generates the
interceptor. `packages/core/src/integrations/hapiInterceptor.ts` emits Java that
consumes the token Signet was configured to mint, and the generated code fails
closed - it accepts only RS384 and ES384, refuses scopes carrying search
parameters it cannot enforce, and restricts patient-context scopes to the Patient
compartment. Use the baseline preset with it.

## Medplum: no preset

Medplum [documents which SMART scopes it
supports](https://www.medplum.com/docs/access/smart-scopes) and implements SMART
App Launch as an authorization server itself. What it does not document is a
contract for consuming a _third-party_ access token: its FHIR API authorises off
tokens Medplum issued, and its [external
authentication](https://www.medplum.com/docs/auth/direct-external-auth) federates
login rather than authorization.

There is therefore nothing to cite, and no Medplum preset. Signet in front of
Medplum is a question of whether Medplum will accept a foreign issuer at all, not
of which claims to mint.
