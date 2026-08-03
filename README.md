# Signet

A multi-tenant [SMART App Launch 2.2.0](https://hl7.org/fhir/smart-app-launch/)
authorization server.

Bring your own FHIR server. Create an _endpoint_ in Signet pointed at it, define
how SMART scopes map to access-token claims, and point your FHIR server's
authorization issuer at Signet. Your server keeps serving FHIR; Signet does
SMART App Launch and SMART Backend Services in front of it.

Built for two things at once:

- **Production FHIR deployments** — per-endpoint signing keys, key rotation,
  audit, and federation to an existing identity provider.
- **Connectathons and SMART app marketplaces** — stand up an endpoint in a
  minute, seed personas, let app developers self-serve a client registration,
  and simulate an EHR launch without an EHR.

## Why the claims mapping matters

Resource servers do not agree on what an access token should look like, and some
do not read SMART scopes at all. [Pathling](https://pathling.csiro.au)
authorizes off its own `authorities` claim, so `patient/Observation.rs` has to
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

In progress. The OAuth server, the admin API, the console, the policy editor and
its simulator, and the end-user surfaces all work end to end. Still to come:
upstream OIDC federation, rate limiting, the Playwright conformance suite, and the
Helm chart's finishing touches.

## Layout

| Path                 | Contents                                                                                                 |
| -------------------- | -------------------------------------------------------------------------------------------------------- |
| `packages/core`      | Pure, I/O-free domain logic — scope grammar, policy engine, tokens, discovery. Exhaustively unit tested. |
| `packages/contracts` | Zod schemas shared between server and web.                                                               |
| `packages/db`        | Drizzle schema, migrations, tenant-scoped repositories.                                                  |
| `apps/server`        | Hono: OAuth endpoints and admin API.                                                                     |
| `apps/web`           | React console, end-user auth pages, developer portal.                                                    |
| `e2e`                | Playwright suite against Signet + Pathling.                                                              |
| `deploy`             | Dockerfile and Helm chart.                                                                               |

`packages/core` holds anything with real logic, as plain functions with no I/O,
so it can be tested directly and reused unchanged by the UI's policy simulator.

## Getting started

Requires [Bun](https://bun.sh) and Docker.

```sh
bun install
cp .env.example .env
bun run test          # unit and integration tests
bun run lint          # eslint
bun run typecheck     # tsc
```

Run the server and the console:

```sh
bun run --filter @signet/server dev     # http://localhost:3000
bun run --filter @signet/web dev        # http://localhost:5173
```

## Container image

```sh
docker build -f deploy/docker/Dockerfile -t signet:dev .
```

The runtime image ships no `node_modules` — the server is bundled into a single
self-contained file. The Dockerfile enforces this: adding a dependency that
cannot be bundled (a native addon) fails the build rather than the deployment.
Prefer WASM or pure-JS dependencies.

## Kubernetes

```sh
helm dependency update deploy/helm/signet
helm install signet deploy/helm/signet --set publicUrl=https://signet.example.org
```

The chart bundles PostgreSQL for evaluation. For production, disable it and
point at a managed instance:

```sh
helm install signet deploy/helm/signet \
  --set postgresql.enabled=false \
  --set database.existingSecret=signet-db \
  --set masterKey.existingSecret=signet-master-key \
  --set publicUrl=https://signet.example.org
```

`SIGNET_MASTER_KEY` encrypts endpoint signing keys at rest. Manage it outside
the chart in production and back it up somewhere other than the database it
protects — if it is lost, every stored signing key becomes undecryptable.

## Putting Signet in front of Pathling

```yaml
PATHLING_AUTH_ENABLED: "true"
PATHLING_AUTH_ISSUER: "https://signet.example.org/t/demo/e/pathling"
PATHLING_AUTH_AUDIENCE: "https://fhir.example.org/fhir"
```

Pathling builds its own `/.well-known/smart-configuration` by merging from the
issuer's OpenID Connect discovery document, so pointing the issuer at a Signet
endpoint is the entire integration.

## Licence

Apache 2.0
