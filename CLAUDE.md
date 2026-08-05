# Signet

A multi-tenant SMART App Launch authorization server. See [README.md](README.md)
for what it does and how to run it.

## Constitution

These are the project's non-negotiable principles. They govern how Signet is
specified, planned, built and reviewed. A change that violates one of them is
rejected in review regardless of how well it works.

### Core principles

#### I. Deny by default (non-negotiable)

Every authorization decision - a scope grant, a token claim, a launch context
value - MUST originate from an explicit rule. No code path may infer permission
from the absence of a prohibition: an unmatched scope is refused, a request with
no resolved tenant sees no rows, an unparseable configuration fails startup
rather than falling back to a default.

New capability MUST be reachable by adding a rule, never by removing a
restriction. A preset or policy that grants a write MUST do so with a rule that
names the write.

Rationale: the failure mode of a forgotten edit must be a rejected request, not
an unintended write to a clinical record. See
`packages/core/src/policy/presets.ts` for the shape this takes in the shipped
presets.

#### II. Tenant isolation is enforced by the compiler, backed by the database (non-negotiable)

Every read or write of tenant-owned data MUST go through a repository function
in `packages/db/src/repositories/` that demands a `TenantScope`, `EndpointScope`
or `ClientScope`. Those values MUST NOT be constructible by hand, so that a
query which has not proved which tenant it belongs to does not compile.

Raw `sql` and the Drizzle handle MUST NOT be used to touch tenant-owned tables
outside that directory. Every tenant-owned table MUST carry a row-level security
policy comparing against `current_setting('signet.tenant_id', true)`, added in
the same migration that creates the table.

Every connection to the database MUST be made as a non-owning role, including
Signet's own. Postgres exempts a table's owner from its policies, so a server, a
reporting job or a `psql` session that connects as the owner is a way past the
isolation that no code review will catch. The owning identity is permitted only
where owner authority is unavoidable - applying migrations, and the cross-tenant
expiry sweep - and MUST NOT be held by a serving process. The server MUST verify
this of its own connection at startup and MUST refuse to serve when the role it
was given turns out to be exempt.

Rationale: the two layers bind different callers, and each is the only thing
binding its own.

The type system binds the application. It fails at build time in every
environment, whether or not anybody configured anything, and it is what stops a
hand-written query or a contributor reaching past the repositories. It also gives
the better diagnostic: a compiler naming a file and a line, rather than a query
that quietly returns nothing.

Row-level security binds every connection whose role is not exempt. That includes
Signet's own, which it did not until the serving role was introduced, and
everything else that reaches the database - a `psql` session, a reporting job, an
analytics tool, a service added later - none of which passes through the compiler
at all.

The reads that must happen before any tenant is known - resolving `/t/{slug}`,
resolving a personal access token's digest, answering which tenants a console user
may see - reach past the policies through an enumerated set of `security definer`
routines rather than through a privileged connection, so the process holds no
handle that can read an arbitrary tenant. That set MUST be declared with a
justification for each member, and a test MUST fail when what the database grants
differs from it.

Neither substitutes for the other, and neither may be dropped on the grounds
that the other exists. See `packages/db/src/rls.ts`, `packages/db/src/privileges.ts`
and the "Tenant isolation in the database" section of `docs/operations.md`.

#### III. Logic lives in pure functions

Anything with real decision logic MUST live in `packages/core` as functions with
no I/O. `apps/server` and `apps/web` compose those functions; they MUST NOT
re-implement the logic they need. React hooks and components stay thin wrappers
over plain functions.

Behaviour MUST be expressed as standalone functions over plain data, not as
methods on objects. The `class` keyword is permitted only where the language
gives no alternative: an `Error` subclass, and a React error boundary. It MUST
NOT be used to hold state or to group behaviour.

Rationale: the console's policy simulator and the token issuer must agree by
construction. Two implementations of the same rule drift, and the drift shows up
as a token that was simulated one way and minted another. A pure core is also
testable without a database or a browser, which is why most of the suite is fast.

#### IV. Prove it, do not claim it (non-negotiable)

Anything Signet advertises MUST be exercised by a test:

- Every value in the `SmartCapability` union MUST have an entry in
  `apps/server/src/conformance.integration.test.ts`. The index is typed as a
  total record over the union, so adding a capability without a test is a compile
  error rather than an omission somebody has to notice.
- A capability that can be turned off MUST be asserted in both directions: an
  endpoint that advertises it does the thing, and one that does not, refuses. An
  affirmative-only test passes against a hard-coded `true`.
- Behaviour claimed in `README.md` or `docs/` MUST be demonstrable by a command
  in the repository.
- The end-to-end path MUST be proven against a real resource server in a real
  browser, not against a mock.

Rationale: a `capabilities` array is a promise to every app that reads it, and
the cheapest way to break it is to change an implementation underneath a
document that still advertises the old behaviour.

### Security requirements

- `SIGNET_MASTER_KEY` lives in the process environment and MUST NOT be written
  to the database it protects, to a log, or to the repository.
- A secret that only ever needs comparing (an account password, an opaque token)
  MUST be hashed, never encrypted. A secret Signet must read back (an endpoint's
  private signing key, an upstream IdP's client secret) MUST be encrypted at
  rest under the master key, with a version tag on the stored ciphertext so a
  later scheme can be introduced without a migration that decrypts everything.
- No credential may reach the audit trail or the logs in plaintext. All audit
  detail MUST pass through `redactAuditDetail`, and call sites MUST NOT build
  detail in a shape the redactor cannot see into - a secret as a bare array
  element, or embedded in a longer string under a harmless key.
- The audit trail is append-only. No code may update or delete an audit row.
- Recording an audit event MUST NOT fail the operation being audited.
- Every endpoint where online guessing pays - the token endpoint, both sign-in
  surfaces, `/authorize` - MUST be rate limited. The limiter's key MUST be
  derived from the client address and route only, never from the request body: a
  key containing a username lets an attacker spread guesses to stay under the
  limit, and one containing a client identifier lets an unauthenticated caller
  exhaust another client's allowance.
- Every outbound HTTP request to an address supplied by anyone other than the
  deployment's operator MUST go through `outboundFetch`. Adding a second path to
  the network is adding a second SSRF surface.

### Quality gates

- Test-driven development is mandatory. Tests that define the expected behaviour
  are written first, run, and seen to fail on assertions before the
  implementation exists.
- CI MUST be green before merge, and the gates MUST NOT be weakened to make a
  change pass: `format:check`, `lint`, `typecheck`, `lint:duplication` at a
  threshold of 0, `test:coverage` at 80% of lines and functions across the whole
  suite, `build`, the container image build and smoke test, the Helm chart lint and
  render, and the end-to-end suite. Coverage thresholds are a floor.

  Lines and functions, not branches: `bun test --coverage` produces no branch data,
  so a branch floor is not something this repository can machine-check. Whether a
  change exercises both sides of the decisions it adds is therefore a review
  question, and reviewers MUST ask it - a rule with a false branch and a rule with
  none are the same line count and the same function count.

  The floor is a total, not a per-file rule. Bun's own `coverageThreshold` is
  applied file by file and its "All files" row is the unweighted mean of the
  per-file percentages, so neither expresses this gate; `scripts/checkCoverage.mjs`
  computes the totals from the lcov report and is what `test:coverage` fails on.

- A test MUST NOT pass by not running. The data layer's integration tests skip
  themselves when `SIGNET_TEST_DATABASE_URL` is unset, so any workflow that is
  supposed to cover them MUST provide a database.
- Every test file MUST live under a package's `src`. `bun test` has no
  ignore-patterns setting, so the scripts narrow discovery with a `src/` filter to
  keep the copies `tsc --build` emits into `dist` from being run as well; a test
  placed outside `src` would silently not run.
- The runtime container ships no `node_modules`; the server is bundled into one
  self-contained file. A dependency that cannot be bundled MUST fail
  `scripts/checkBundle.mjs` in the Docker build rather than the deployment.
  Prefer WASM or pure-JavaScript dependencies.
- Every user-visible operation MUST report its own state: a pending request, a
  failure with its cause, a successful write. Silence is not an acceptable
  response to an action.

### Amendment

Amending this constitution is a deliberate act, made in its own commit, with the
rationale in the commit body. A principle that is being worked around rather
than followed is either wrong and should be amended, or right and the work-around
should be removed - it MUST NOT be left ambiguous.
