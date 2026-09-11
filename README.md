# Signet

[![CI](https://github.com/aehrc/signet/actions/workflows/ci.yml/badge.svg)](https://github.com/aehrc/signet/actions/workflows/ci.yml)
[![Licence: Apache 2.0](https://img.shields.io/badge/licence-Apache%202.0-blue.svg)](LICENSE)

A multi-tenant [SMART App Launch 2.2.0](https://hl7.org/fhir/smart-app-launch/)
authorization server.

Bring your own FHIR server. Create an _endpoint_ in Signet pointed at it, define
how SMART scopes map to access-token claims, and point your FHIR server's
authorization issuer at Signet. Your server keeps serving FHIR; Signet does
SMART App Launch and SMART Backend Services in front of it.

Stand up an endpoint in a minute, seed personas, let app developers request a
client registration, and simulate an EHR launch without an EHR. Each endpoint
has its own signing keys with rotation, an append-only audit trail, and can
federate to an existing identity provider.

## Claims mapping

Resource servers do not agree on what an access token should look like, and some
do not read SMART scopes at all. Signet makes the translation from scope to claim
a declarative, versioned policy, edited in the console and tested against a live
token simulator, rather than a code change in the authorization server.

Presets ship for the servers whose claim contract is documented, each carrying
the citation it was written from. See
[docs/resource-servers.md](docs/resource-servers.md).

## Client registration

Dynamic client registration (RFC 7591) is refused on every endpoint by default:
no registration endpoint is served or advertised. An endpoint that names a
**trust anchor** registers a client for a software statement signed by that
anchor, and refuses statements from anybody else. Otherwise a developer submits a
request at `{iss}/apps`, an administrator approves it in the console, and the
developer collects the credentials.

## Layout

| Path                 | Contents                                                                       |
| -------------------- | ------------------------------------------------------------------------------ |
| `packages/core`      | Pure, I/O-free domain logic - scope grammar, policy engine, tokens, discovery. |
| `packages/contracts` | Zod schemas shared between server and web.                                     |
| `packages/db`        | Drizzle schema, migrations, tenant-scoped repositories.                        |
| `apps/server`        | Hono: OAuth endpoints and admin API.                                           |
| `apps/web`           | React console, end-user auth pages, developer portal.                          |
| `e2e`                | Playwright suite driving a real SMART launch against a real FHIR server.       |
| `deploy`             | Helm chart, and the docker-compose stack the end-to-end suite runs against.    |
| `docs`               | What each resource server wants in a token, and how to run Signet.             |

## Getting started

Requires [Bun](https://bun.sh) and Docker.

```sh
bun install
cp .env.example .env.test
cp apps/server/.env.example apps/server/.env.local
cp packages/db/.env.example packages/db/.env.local
overmind start        # server on http://localhost:3000, console on http://localhost:5173
bun run test          # unit and integration tests
```

Each `.env.example` documents its variables and which file they belong in. The
integration suites skip themselves when `SIGNET_TEST_DATABASE_URL` is unset, so a
`bun run test` that finishes in seconds with a `skip` count has not exercised the
database.

The end-to-end stack builds the container image and runs it alongside Postgres,
a FHIR server and a stub SMART app:

```sh
bun run stack:up      # build and start; waits for health
bun run stack:seed    # endpoint, policy, clients and accounts
bun run test:e2e      # drive a launch through a browser
bun run stack:down
```

Open `http://localhost:3000/console` to look at the seeded endpoint. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the rest of the development workflow.

## Deployment

Released images are published to `ghcr.io/aehrc/signet` for `linux/amd64` and
`linux/arm64`, and the chart installs one of them by default. To build the image
yourself:

```sh
docker build -t signet:dev .
```

The runtime image ships no `node_modules`; the server is bundled into a single
self-contained file, and the build fails on a dependency that cannot be bundled.

```sh
helm install signet deploy/helm/signet \
  --set signet.postgres.enabled=false \
  --set signet.database.existingSecret=signet-db \
  --set signet.database.ownerExistingSecret=signet-db-owner \
  --set signet.masterKey.existingSecret=signet-master-key \
  --set signet.config.SIGNET_PUBLIC_URL=https://signet.example.org
```

The chart bundles PostgreSQL for evaluation; leave `signet.postgres.enabled` at
its default to use it. Every value is documented in
[deploy/helm/signet/README.md](deploy/helm/signet/README.md).

`SIGNET_MASTER_KEY` encrypts endpoint signing keys at rest. Manage it outside the
chart and back it up somewhere other than the database it protects; if it is
lost, every stored signing key becomes undecryptable.

Configuration, tenant isolation, key rotation and troubleshooting are covered in
[docs/operations.md](docs/operations.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to report a bug, propose a
resource server preset, and what a change has to satisfy to be merged. The
project's non-negotiable principles are in [CLAUDE.md](CLAUDE.md).

## Licence

Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
(CSIRO) ABN 41 687 119 230.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0).

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the [LICENSE](LICENSE)
file for the specific language governing permissions and limitations under the
License.

## Disclaimer

Signet is experimental software. It has not been independently security reviewed
and must not be used to protect sensitive data, including real patient records.
It is intended for connectathons, demonstrations and development against
synthetic data.
