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
authorises off its own `authorities` claim, so `patient/Observation.rs` has to
become `["pathling:read:Observation", "pathling:search"]` before Pathling will
honour it.

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

### Deliberately not built

**Dynamic client registration** (`POST {iss}/register`, RFC 7591). Signet serves
no registration endpoint and advertises none, so a client cannot obtain
credentials by asking for them.

The developer portal at `{iss}/apps` is the alternative, and it is a different
trade rather than a smaller one: a developer submits a request, an administrator
approves it in the console, and the developer then collects the credentials. That
puts a person between "anybody who can reach this endpoint" and "holds a client
credential on it", which is the property worth having on a server whose endpoints
front clinical data.

`apps/server/src/conformance.integration.test.ts` asserts both halves - nothing is
advertised, and `/register` answers 404 - so this stays a decision rather than
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

Run the server and the console:

```sh
bun run --filter @signet/server dev     # http://localhost:3000
bun run --filter @signet/web dev        # http://localhost:5173
```

### Configuration

There are three `.env.example` files, one beside each thing that reads an
environment, and each says which of its variables belongs in which file:

```sh
cp .env.example .env.test               # the test database, for `bun run test`
cp apps/server/.env.example apps/server/.env.local
cp packages/db/.env.example packages/db/.env.local
```

Two rules of Bun's decide the layout, and both are easy to be caught by. Bun loads
`.env` files from the working directory and does not search upwards, not even for its
own `bun run --filter`, which runs each script in its package's directory. And
`bun test` sets `NODE_ENV=test`, in which mode Bun loads `.env` and `.env.test` but
**not** `.env.local`.

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

Signet, Pathling, Postgres and a stub SMART app, built from the production image:

```sh
bun run stack:up      # build and start; waits for health
bun run stack:seed    # create the endpoint, policy, clients and accounts
bun run test:e2e      # drive a launch through a browser
bun run stack:down
```

Then open `http://localhost:4000/?iss=http://localhost:3000/t/demo/e/pathling` to
run a launch by hand, or `http://localhost:3000/console` to look at the endpoint
that served it. If port 3000 is taken, set `SIGNET_PORT` - it moves the stack and
every issuer identifier with it.

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
