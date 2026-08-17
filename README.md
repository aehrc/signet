# Signet

A multi-tenant [SMART App Launch 2.2.0](https://hl7.org/fhir/smart-app-launch/)
authorization server.

Bring your own FHIR server. Create an _endpoint_ in Signet pointed at it, define
how SMART scopes map to access-token claims, and point your FHIR server's
authorization issuer at Signet. Your server keeps serving FHIR; Signet does
SMART App Launch and SMART Backend Services in front of it.

Built for two things at once:

- **Production FHIR deployments** - per-endpoint signing keys, key rotation,
  audit, and federation to an existing identity provider.
- **Connectathons and SMART app marketplaces** - stand up an endpoint in a
  minute, seed personas, let app developers self-serve a client registration,
  and simulate an EHR launch without an EHR.

## Why the claims mapping matters

Resource servers do not agree on what an access token should look like, and some
do not read SMART scopes at all. [Pathling](https://pathling.csiro.au)
authorises off its own `authorities` claim, so before Pathling will honour
`patient/Observation.rs` that scope has to become a data authority naming the
resource type, `pathling:read:Observation`, plus one operation authority for
each interaction the scope allows - `pathling:search` and the rest.

Signet makes that translation a declarative, versioned policy you edit in the UI
and test against a live token simulator, rather than a code change in the
authorization server.

Presets ship for the servers whose claim contract is documented - SMART baseline,
Pathling, Aidbox, Firely Server, Smile CDR - and each one carries the citation it
was written from. See [docs/resource-servers.md](docs/resource-servers.md) for what
each server wants, and for the two servers that get no preset and why.

## Status

Complete and exercised end to end. A Playwright suite drives a real SMART launch
in a browser against a docker-compose stack of Signet, Pathling and a stub app,
and asserts that Pathling accepts the token Signet minted.

See [docs/operations.md](docs/operations.md) for configuration, key rotation and
deployment.

### No open registration; vouched registration by explicit rule

**Dynamic client registration** (`POST {iss}/register`, RFC 7591) is refused on
every endpoint by default. Signet serves no registration endpoint and advertises
none, so a client cannot obtain credentials on an endpoint by asking for them.

An endpoint that names a **trust anchor** is the exception, and it is a narrow
one. The rule names an issuer and the address where that issuer publishes its
keys, and it is the whole of the capability: with it, the endpoint registers a
client for a software statement signed by that anchor, and refuses statements
from anybody else; without it, `/register` answers 404 and both discovery
documents advertise nothing. There is no flag to turn on beside the rule, and no
setting that opens registration to the world.

What the anchor's signature buys is the vetting, not the metadata's validity. The
client is created from the statement's own metadata and nothing asserted beside
it, that metadata still has to pass the checks any other client's does, one
statement registers exactly one client, and the registration expires when the
statement says the vouching does - after which every grant type refuses the
client until it registers again.

The developer portal at `{iss}/apps` remains the alternative for an endpoint with
no anchor to trust: a developer submits a request, an administrator approves it
in the console, and the developer then collects the credentials. Both routes put
something between "anybody who can reach this endpoint" and "holds a client
credential on it" - a person in one case, a signature from a named issuer in the
other.

`apps/server/src/conformance.integration.test.ts` asserts both directions -
nothing advertised and `/register` answering 404 without a rule, the endpoint
advertised and registering with one - so this stays a decision rather than
drifting into an accident.

## Layout

| Path                 | Contents                                                                                                 |
| -------------------- | -------------------------------------------------------------------------------------------------------- |
| `packages/core`      | Pure, I/O-free domain logic - scope grammar, policy engine, tokens, discovery. Exhaustively unit tested. |
| `packages/contracts` | Zod schemas shared between server and web.                                                               |
| `packages/db`        | Drizzle schema, migrations, tenant-scoped repositories.                                                  |
| `apps/server`        | Hono: OAuth endpoints and admin API.                                                                     |
| `apps/web`           | React console, end-user auth pages, developer portal.                                                    |
| `e2e`                | Playwright suite against Signet + Pathling.                                                              |
| `deploy`             | Helm chart, and the docker-compose stack the end-to-end suite runs against.                              |
| `docs`               | What each resource server wants in a token, and how to run Signet.                                       |

`packages/core` holds anything with real logic, as plain functions with no I/O,
so it can be tested directly and reused unchanged by the UI's policy simulator.

## Getting started

Requires [Bun](https://bun.sh) and Docker.

```sh
bun install
bun run test          # unit and integration tests, via bun test
bun run lint          # eslint
bun run typecheck     # tsc
```

Run the server and the console via the `Procfile`:

```sh
overmind start     # server on http://localhost:3000, web on http://localhost:5173
```

### Configuration

There are three `.env.example` files, one beside each thing that reads an
environment, and each says which of its variables belongs in which file:

```sh
cp .env.example .env.test               # the test database, for `bun run test`
cp apps/server/.env.example apps/server/.env.local
cp packages/db/.env.example packages/db/.env.local
```

Three rules of Bun's decide the layout, and each is easy to be caught by. Bun loads
`.env` files from the working directory and does not search upwards, not even for its
own `bun run --filter`, which runs each script in its package's directory. `bun test`
sets `NODE_ENV=test`, in which mode Bun loads `.env` and `.env.test` but **not**
`.env.local`. And Bun loads these files into its own process without passing what it
loaded to the processes it spawns, so a variable read by something Bun merely launches
(`docker compose`, Playwright) has to be exported into the shell rather than written
to a file. The stack's ports are the whole of that case; see below.

So `SIGNET_TEST_DATABASE_URL` goes in `.env.test`, and leaving it out is quiet rather
than loud: the integration suites skip themselves and the run still reports success.
If `bun run test` finishes in a couple of seconds with a `skip` count, that is what
has happened.

`bun run test` covers everything. A single package or file is a path filter, from the
repository root:

```sh
bun test packages/db/src/                       # one package
bun test packages/core/src/policy/              # one directory
bun test src/ -t "refuses a wrong password"     # by test name
```

## The end-to-end stack

Signet, Pathling, Postgres and a stub SMART app, built from the production image.
Pathling is `ghcr.io/aehrc/pathling:3.0.0-SNAPSHOT`, the pre-release the Pathling
preset is written against; a released Pathling cannot parse the hyphenated
operation authorities the preset mints, and fails every request rather than
ignoring what it does not recognise.

```sh
bun run stack:up      # build and start; waits for health
bun run stack:seed    # endpoint, policy, clients, accounts and two requests
bun run test:e2e      # drive a launch through a browser
bun run stack:down
```

Then open `http://localhost:4000/?iss=http://localhost:3000/t/demo/e/pathling` to
run a launch by hand, or `http://localhost:3000/console` to look at the endpoint
that served it.

### Moving the stack's ports

Three variables move it - `SIGNET_PORT` (3000), `PATHLING_PORT` (8080) and
`APP_PORT` (4000) - and each moves every URL derived from it, issuer identifiers
included.

**Export them.** They must be in the environment of the shell that runs the
commands, not in `.env.local`: `docker compose` and Playwright are processes Bun
launches, and Bun does not pass a variable it loaded from a file to a process it
launches. A `SIGNET_PORT` in `.env.local` publishes the stack on 3000 anyway.

```sh
export SIGNET_PORT=3100 PATHLING_PORT=8180 APP_PORT=4100
bun run stack:up
bun run test:e2e
```

`stack:up`, `stack:seed` and `test:e2e` all read them and all have to agree, so
export once per shell rather than prefixing each command - `direnv` and an `.envrc`
if you would rather not do even that.

`stack:seed` is the only one of the three that Bun runs in its own process, so it is
the only one that could read a port from a file and disagree with the stack. It
refuses to run when it finds one there, and says so. An `.envrc` is not one of those
files: direnv exports what it declares, so every command sees it.

CI runs the whole end-to-end job on `3100`, `8180` and `4100`, so a URL that goes
back to being hard-coded fails there rather than on the machine that needed it.

## Narrow viewports

**360 CSS pixels is the narrowest supported width**, and it applies to all three
surfaces: the console, the end-user authorization pages and the developer portal.
Below 360px nothing is promised. "Mobile" here means a narrow viewport and not a
user agent - a desktop window dragged to 500px gets the same rendering a phone
does, and no code anywhere sniffs a user agent to decide.

What changes below Tailwind's `sm` breakpoint (640px):

- **Lists become cards.** Every console list rendered by the shared table
  component - endpoints, clients, users, keys, registration requests, audit,
  policy versions - renders as one card per row instead of a table: the first
  column becomes the card's title, every other column a labelled value, and the
  row's actions stay with it. Nothing is dropped. A table at 360px would put its
  last columns off the edge of the screen, which is what this replaces. At 640px
  and above the table is what renders, unchanged.
- **Side-by-side becomes stacked.** Forms are one column, and the policy editor's
  rule list, rule builder and simulator sit one above the other. No capability is
  removed on a narrow viewport: every field, control and output present on a
  desktop is present here.
- **Controls grow.** Every interactive element offers at least a 44x44 pixel
  target, and every form control renders its text at no less than 16px, which is
  the size below which a mobile browser zooms a focused field and does not zoom
  back out.
- **Wide content scrolls inside itself.** A token, a JWKS URL, a JSON claim set
  or a policy diff scrolls or wraps within its own container. The page body never
  scrolls sideways.

The 16px floor covers form controls, the body text a panel inherits, and running
prose - descriptions, hints, validation and status messages. It does not cover
the annotation layer: the labels inside a card, badges, timestamps, monospace
identifiers, code and diffs, which stay denser by design. The reading, and why,
is written down at the top of `apps/web/src/components/layout.tsx`.

### Proving it

None of the above is asserted by hand. `e2e/tests/responsive.spec.ts` runs under
a second Playwright project, `mobile`, at a 360x780 viewport:

```sh
bun run stack:up
cd e2e
bunx playwright test responsive --project=mobile
```

It carries a full SMART launch through sign-in, patient selection and consent at
that viewport, sweeps every console, end-user and portal route asserting no
horizontal page overflow with the navigation drawer both closed and open, drives
the policy editor, the token simulator and the launch simulator, and measures
every visible control's box and font size. The card rendering is asserted at the
mobile viewport and the table rendering at 640px, so both directions of the
switch are covered. The desktop suite is a separate project and shares no
assertions with it:

```sh
bunx playwright test --project=chromium
```

**One run of the suite per minute.** End-user sign-ins are rate limited to ten a
minute per address and a full run spends most of that allowance; a second run
started inside the window is refused, which shows up as a sign-in page that will
not proceed. That is the limiter working, not the layout failing.

## Container image

```sh
docker build -t signet:dev .
```

The runtime image ships no `node_modules` - the server is bundled into a single
self-contained file. The Dockerfile enforces this: adding a dependency that
cannot be bundled (a native addon) fails the build rather than the deployment.
Prefer WASM or pure-JS dependencies.

## Kubernetes

```sh
helm install signet deploy/helm/signet \
  --set signet.config.SIGNET_PUBLIC_URL=https://signet.example.org
```

The chart bundles PostgreSQL for evaluation. For production, disable it and
point at a managed instance:

```sh
helm install signet deploy/helm/signet \
  --set signet.postgres.enabled=false \
  --set signet.database.existingSecret=signet-db \
  --set signet.database.ownerExistingSecret=signet-db-owner \
  --set signet.masterKey.existingSecret=signet-master-key \
  --set signet.config.SIGNET_PUBLIC_URL=https://signet.example.org
```

Every value the chart takes is documented in
[deploy/helm/signet/README.md](deploy/helm/signet/README.md).

`SIGNET_MASTER_KEY` encrypts endpoint signing keys at rest. Manage it outside
the chart in production and back it up somewhere other than the database it
protects - if it is lost, every stored signing key becomes undecryptable.

## Putting Signet in front of Pathling

```yaml
PATHLING_AUTH_ENABLED: "true"
PATHLING_AUTH_ISSUER: "https://signet.example.org/t/demo/e/pathling"
PATHLING_AUTH_AUDIENCE: "https://fhir.example.org/fhir"
```

Pathling builds its own `/.well-known/smart-configuration` by merging from the
issuer's OpenID Connect discovery document, so pointing the issuer at a Signet
endpoint is the entire integration.

## Copyright

Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
(CSIRO) ABN 41 687 119 230.

All rights reserved. Signet is not open source and carries no licence to use,
copy, modify or distribute it.
