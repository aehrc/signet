# Running Signet

What an operator needs after the first deployment: how keys are rotated, what the
master key protects, what each configuration value does, and what to do when
something is wrong.

## Configuration

| Variable                                | Required | What it does                                                                                                                                                                                                                                            |
| --------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PORT`                                  | no       | Listen port. Defaults to 3000.                                                                                                                                                                                                                          |
| `SIGNET_PUBLIC_URL`                     | yes      | The origin Signet is reached on. **Every issuer identifier is derived from it**, so changing it invalidates every issuer already published to FHIR servers and registered with apps.                                                                    |
| `SIGNET_DATABASE_URL`                   | yes      | Postgres connection string. `SIGNET_DATABASE_HOST`/`_PORT`/`_NAME`/`_USER`/`_PASSWORD` are accepted instead, which is what the Helm chart uses when it wires up the bundled subchart.                                                                   |
| `SIGNET_MASTER_KEY`                     | yes      | Encrypts endpoint signing keys and upstream client secrets at rest. At least 32 characters. See below.                                                                                                                                                  |
| `SIGNET_LOG_LEVEL`                      | no       | `debug`, `info`, `warn` or `error`. Defaults to `info`.                                                                                                                                                                                                 |
| `SIGNET_WEB_ROOT`                       | no       | Directory of the built console. Set in the image; unset in development, where Vite serves it.                                                                                                                                                           |
| `SIGNET_ALLOW_PRIVATE_OUTBOUND_FETCHES` | no       | Turns off the SSRF guard on outbound fetches. For a development or connectathon stack whose identity provider is on a private address. **Never set this in production** - see `apps/server/src/security/outboundFetch.ts` for exactly what it disables. |

Commands, all on the same image:

```sh
node dist/index.js            # serve
node dist/index.js migrate    # apply migrations, then exit
node dist/index.js bootstrap  # create the first tenant and administrator, then exit
```

`migrate` and `bootstrap` need only a database connection - not the public URL or
the master key - so a migration job's manifest stays minimal.

## The master key

`SIGNET_MASTER_KEY` is the envelope key for every endpoint's private signing key
and for the client secrets Signet presents to upstream identity providers. It is
the one secret whose loss cannot be recovered from inside the system:

- **Losing it** makes every stored signing key undecryptable. Endpoints stop
  issuing tokens until new keys are generated, which changes every `kid` and
  invalidates every token already in flight.
- **Disclosing it** is equivalent to disclosing every endpoint's private key,
  because the ciphertext is in a database that more people can read than can read
  the key.

So: manage it outside the chart, back it up somewhere other than the database it
protects, and rotate it deliberately rather than incidentally. There is no
"rotate the master key" command yet; doing it today means generating new endpoint
keys under the new master key and retiring the old ones, which is the rotation
runbook below with an extra step.

## Rotating an endpoint's signing key

Rotation is three actions rather than one button, and the gaps between them are
the point. A relying party caches a JWKS; a key that appears and immediately signs
is a key nobody has cached, and every token it signs is rejected until the cache
expires.

**1. Generate.** Console → the endpoint → Keys → _Generate_, or
`POST /api/v1/tenants/{tenant}/endpoints/{endpoint}/keys` with an algorithm. The
new key is created as `next`: published in the JWKS immediately, signing nothing.

**2. Wait.** Long enough for every relying party to have refetched the JWKS.
Signet serves discovery and JWKS with `Cache-Control: public, max-age=300`, so
five minutes covers anything that honours it; an hour covers most things that do
not. There is no cost to waiting longer.

**3. Promote.** Console → Keys → _Promote_, or
`POST .../keys/promote`. This is a swap inside one transaction: the `next` key
becomes `active` and the previous `active` becomes `retired`. There is never an
instant with two active keys or none.

**4. Retire, later.** A retired key stops being published, so any token it signed
becomes unverifiable. Wait for the longest access token lifetime the endpoint
issues - one hour by default - before
`POST .../keys/{kid}/retire`. Retiring early does not break anything a relying
party has already cached; it breaks tokens still in use.

If a key is believed compromised, do steps 1 and 3 immediately and step 4 straight
after. Every token the old key signed becomes unverifiable, which is the intended
outcome: revoking the tokens themselves through
`POST {iss}/revoke` is cleaner where the list of tokens is known.

### Choosing an algorithm

`ES384` by default, `RS384` where a relying party asks for RSA, and `RS256` only
for a resource server whose JWT decoder accepts nothing else. That last case is
not hypothetical: Spring Security's decoder defaults to RS256, and several FHIR
servers - Pathling among them - build theirs from an issuer URL without
configuring the algorithm. Such a server rejects an RS384 token with "another
algorithm expected", which sends an operator looking at their keys rather than at
a default they cannot see.

The endpoint's discovery document advertises the algorithms its published keys
actually use, so a relying party configuring a verifier from it accepts what the
endpoint signs with.

## Deploying on Kubernetes

```sh
helm dependency update deploy/helm/signet
helm install signet deploy/helm/signet \
  --set publicUrl=https://signet.example.org
```

That brings up Signet with a bundled PostgreSQL, which is for evaluation. For
production, point at a managed instance and supply both secrets from outside the
chart:

```sh
kubectl create secret generic signet-db --from-literal=url='postgres://…'
kubectl create secret generic signet-master-key --from-literal=masterKey='…'

helm install signet deploy/helm/signet \
  --set postgresql.enabled=false \
  --set database.existingSecret=signet-db \
  --set masterKey.existingSecret=signet-master-key \
  --set publicUrl=https://signet.example.org \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=signet.example.org
```

What the chart does that is worth knowing:

- **Migrations run as a pre-install and pre-upgrade hook**, before new pods roll
  out. An upgrade whose migration fails does not replace the running pods.
- **Probes are separate.** `/healthz` is liveness and answers from the process
  alone; `/readyz` is readiness and consults the database, so a pod that has lost
  its connection is taken out of the load balancer rather than restarted.
- **The root filesystem is read-only** and the container runs unprivileged, with
  `/tmp` mounted as the one writable path.
- **Replicas spread across nodes** by default, and a PodDisruptionBudget keeps one
  available through a drain. An authorization server that is down takes every app
  in front of it with it.
- **Autoscaling is off by default.** Turn it on with `autoscaling.enabled=true`;
  the defaults scale on CPU between two and ten replicas.

### What to put in front of it

Signet expects to be behind something that terminates TLS and sets
`X-Forwarded-For`. Two consequences:

- **Strip inbound `X-Forwarded-For`.** Signet reads it for the audit trail and for
  rate-limit keys, so an ingress that passes a client-supplied value through lets
  a caller choose both.
- **Rate limiting is per process.** With `n` replicas the effective limit is up to
  `n` times what is configured. It is there to defeat online guessing, which a
  small integer factor does not rescue; a deployment that needs an exact global
  limit should set it at the ingress.

## When something is wrong

**An app gets `invalid_client`.** The client's `client_id` is unknown at that
endpoint, or its secret is wrong, or it is suspended. The audit trail records
`token.denied` with the reason; the console's audit browser filters by action.

**A FHIR server rejects every token.** Compare three things: the `iss` in the
token against the issuer the FHIR server is configured with (exact string match,
trailing slash included), the `aud` against its expected audience, and the
algorithm in the token header against what its verifier accepts. The conformance
suite asserts the first two are consistent within Signet; the third is the RS256
case above.

**A federated sign-in fails.** Console → the endpoint → Identity → _Check the
provider_. It fetches the discovery document through the same guard the sign-in
uses and reports exactly what it found. Failures are also in the audit trail as
`end-user.login-failed` with `surface: federation` and a specific reason, which
the browser deliberately never sees.

**Everything is 500.** Almost always an unmigrated database. `/readyz` fails too;
`node dist/index.js migrate` fixes it.
