# Running Signet

What an operator needs after the first deployment: how keys are rotated, what the
master key protects, what each configuration value does, and what to do when
something is wrong.

## Configuration

| Variable                                | Required           | What it does                                                                                                                                                                                                                                                |
| --------------------------------------- | ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PORT`                                  | no                 | Listen port. Defaults to 3000.                                                                                                                                                                                                                              |
| `SIGNET_PUBLIC_URL`                     | yes                | The origin Signet is reached on. **Every issuer identifier is derived from it**, so changing it invalidates every issuer already published to FHIR servers and registered with apps.                                                                        |
| `SIGNET_DATABASE_URL`                   | yes                | Postgres connection string, naming the **serving role** - which must own none of Signet's tables. `SIGNET_DATABASE_HOST`/`_PORT`/`_NAME`/`_USER`/`_PASSWORD` are accepted instead, which is what the Helm chart uses when it wires up the bundled subchart. |
| `SIGNET_DATABASE_OWNER_URL`             | `migrate`, `sweep` | The **owning identity**, read by those two commands and by nothing else. See [the two database identities](#the-two-database-identities).                                                                                                                   |
| `SIGNET_SWEEP_ACCESS_TOKEN_GRACE`       | no                 | How far the `sweep` command's access token cut-off lags the present, as a whole number and a unit - `24h`, `30m`, `7d`. Defaults to `24h`. See [the expiry sweep](#the-expiry-sweep).                                                                       |
| `SIGNET_MASTER_KEY`                     | yes                | Encrypts endpoint signing keys and upstream client secrets at rest. At least 32 characters. See below.                                                                                                                                                      |
| `SIGNET_LOG_LEVEL`                      | no                 | `debug`, `info`, `warn` or `error`. Defaults to `info`.                                                                                                                                                                                                     |
| `SIGNET_WEB_ROOT`                       | no                 | Directory of the built console. Set in the image; unset in development, where Vite serves it.                                                                                                                                                               |
| `SIGNET_ALLOW_PRIVATE_OUTBOUND_FETCHES` | no                 | Turns off the SSRF guard on outbound fetches. For a development or connectathon stack whose identity provider is on a private address. **Never set this in production** - see `apps/server/src/security/outboundFetch.ts` for exactly what it disables.     |

Commands, all on the same image:

```sh
node dist/index.js            # serve
node dist/index.js migrate    # apply migrations, then exit
node dist/index.js bootstrap  # create the first tenant and administrator, then exit
node dist/index.js sweep      # delete expired rows across every tenant, then exit
```

None of the three sub-commands needs the public URL or the master key - a job's
manifest stays minimal - but they do not all need the same identity. `migrate` and `sweep` need
the one owning the schema, for different reasons: migrations are DDL, and the
sweep acts across tenants. `bootstrap` runs as the serving role like the server
does. See [the two database identities](#the-two-database-identities).

## Tenant isolation in the database

Signet enforces tenancy twice, and the two layers fail in different ways on
purpose.

The first is the type system. Every function in
`packages/db/src/repositories/` demands a `TenantScope`, `EndpointScope` or
`ClientScope`, and none of those can be written down by hand - they are only
produced by resolving a tenant. A query that has not proved which tenant it
belongs to does not compile. This is the layer that matters most, because it
fails at build time in every environment whether or not anybody configured
anything.

The second is Postgres row-level security. Migration
`0006_tenant_row_level_security` enables RLS on all 21 tenant-owned tables and
creates a `signet_tenant_isolation` policy on each, comparing against
`current_setting('signet.tenant_id', true)`. Because the second argument makes a
missing setting return NULL, and a NULL comparison is not true, a connection that
never set the variable sees no tenant-owned rows at all. Forgetting it yields an
obviously empty result rather than a quietly cross-tenant one.

You get the policies by running migrations. There is nothing extra to install:

```bash
node dist/index.js migrate
```

Verify them on any database you are unsure about:

```sql
select tablename from pg_policies where policyname = 'signet_tenant_isolation';
```

### The two database identities

This is the part to get right before relying on the policies, because **Postgres
exempts a table's owner from that table's policies**. A Signet connecting as the
owner of its tables would have the policies installed and be unconstrained by
them. So a deployment runs two identities:

| Identity            | Owns the schema | Policies apply | Used by                            |
| ------------------- | --------------- | -------------- | ---------------------------------- |
| **Owning identity** | yes             | no             | `migrate` and `sweep`              |
| **Serving role**    | no              | yes            | the server, `bootstrap`, the suite |

`SIGNET_DATABASE_URL` names the serving role - it keeps the meaning it always
had, and what changed is that the role it names must be non-owning.
`SIGNET_DATABASE_OWNER_URL` names the owning identity and is read by `migrate`
and `sweep` alone, so the owner credential reaches a job rather than sitting in
the running pod. `migrate` reads both: it connects as the owner, and it takes the
serving role's _name_ from `SIGNET_DATABASE_URL` in order to grant it - it never
uses that role's password. Two URLs naming the same role are refused, because that
deployment could not enforce isolation. `sweep` reads only the owner URL, and
checks that the role it names is in fact exempt before it deletes anything.

Creating the serving role, if you are not using the bundled compose stack or the
Helm chart. Nothing is granted here - `migrate` issues the grants, as the owning
identity, immediately after applying the migrations, so a table added by a later
migration cannot ship ungranted:

```sql
create role signet_app login password '...';
```

Then, once per deployment and on every upgrade:

```bash
SIGNET_DATABASE_OWNER_URL=postgres://owner:...@host/signet \
SIGNET_DATABASE_URL=postgres://signet_app:...@host/signet \
  node dist/index.js migrate
```

The bundled compose stack does this itself: `deploy/compose/initdb` creates the
role on first initialisation and the `migrate` service applies the migrations as
the owner. The Helm chart needs no role created at all - the bundled PostgreSQL
subchart's superuser owns the schema and its custom user, which the server
connects as, owns nothing.

### The server refuses to serve when it cannot enforce

Which identity a server holds is configuration, so it is something a deployment
can get wrong without any code being wrong. The server therefore checks, on the
connection it is about to serve on, before it begins listening, and reports the
outcome either way:

```
{"level":"info","message":"signet.enforcement.verified","role":"signet_app","tablesVerified":21}
```

Three outcomes are refusals, and they exit 1 with different remedies because they
have different causes:

| Refusal                   | What it means                                                                  | What to do                                      |
| ------------------------- | ------------------------------------------------------------------------------ | ----------------------------------------------- |
| **Schema absent**         | The covered tables do not exist, or row-level security is off on one           | Run `migrate` with the owning identity          |
| **Role exempt**           | The role owns a covered table, belongs to a role that does, or has `BYPASSRLS` | Point `SIGNET_DATABASE_URL` at the serving role |
| **Role under-privileged** | The role is bound by the policies but cannot reach a table it needs            | Re-run `migrate`, which issues the grants       |

The middle one is the one worth reading closely: it names the exemption it found,
and it is what a deployment given the owner credential by mistake gets instead of
months of appearing to work.

### Verifying enforcement on a running deployment

From outside the process, which is the point - the server's own report is only
worth as much as the process making it. Both questions, as the owning identity:

```sql
-- 1. The role the server connects as must hold no bypass and own nothing.
select rolname, rolbypassrls, rolsuper from pg_roles where rolname = 'signet_app';

select count(*) as covered_tables_owned
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
 where n.nspname = 'public'
   and c.relkind = 'r'
   and pg_has_role('signet_app', c.relowner, 'usage');

-- 2. Every covered table must have row-level security enabled and the policy on it.
select count(*) as policies from pg_policies
 where policyname = 'signet_tenant_isolation';
```

Enforcement holds when the first returns `f`/`f`, the second returns 0, and the
third returns 21. The membership test in the second is not a formality: a role
added to the owning role inherits the owner's exemption while looking correct in
every other respect, which is why it asks `pg_has_role` rather than comparing
names.

You can also see it directly. As the serving role, a query that has named no
tenant returns nothing, and naming one returns only that tenant's rows:

```sql
select count(*) from endpoints;                                  -- 0
select set_config('signet.tenant_id', '<tenant uuid>', false);
select count(*) from endpoints;                                  -- that tenant's
```

### What the process can still do without a tenant

The exemption is not zero, and it is a list rather than a capability. Three
`security definer` routines, created by migration `0007_serving_role_privileges`
and declared with a justification each in `packages/db/src/privileges.ts`, turn an
identifier a request already carried into a tenant - which necessarily precedes
knowing one:

```sql
select routine_name from information_schema.routines
 where routine_schema = 'public' and routine_name like 'signet\_%';
```

Each takes an identifier and returns identifiers only. None returns
configuration, so a tenant's FHIR base URL, TTLs and capability flags stay out of
reach of an unbound caller. The suite asserts that what the serving role may
execute equals that declared set exactly, so a fourth routine fails a test rather
than widening the exemption quietly.

### Other connections to the database

The policies bind every connection whose role is not exempt, which now includes
Signet's own. That leaves the connections a mistake is most likely to reach the
data through and least likely to have gone through the repositories: a `psql`
session, a reporting job, an analytics tool, a backup verification script, a
service added later. **Give each of them a non-owning role**, because connecting
as the owner is a way past the isolation that no code review will catch:

```sql
create role signet_reader login password '...';
grant usage on schema public to signet_reader;
grant select on all tables in schema public to signet_reader;
alter default privileges in schema public
  grant select on tables to signet_reader;
```

A `signet_reader` session then sees nothing until it names a tenant, and only
that tenant's rows afterwards:

```sql
select set_config('signet.tenant_id', '<tenant uuid>', false);
select slug from endpoints;
```

### The expiry sweep

`node dist/index.js sweep` deletes expired authorization codes, sessions, tokens,
consents, `jti` records and passkey ceremony challenges. It operates on rows from
every tenant, which is what a maintenance job is for, and is therefore the one
path besides `migrate` that **needs the owning identity**. Attempted with the
serving role it deletes nothing at all rather than partially succeeding - the
policies hide every row from a connection that has declared no tenant - so its
existence gives the server no cross-tenant capability. Both directions are
asserted in `packages/db/src/repositories/repositories.integration.test.ts`.

Every row it removes is already expired and refused on the strength of its own
`expires_at`, so the sweep reclaims storage and can grant or revoke nothing, and
nothing breaks on a deployment that skips a run. What makes it worth scheduling is
`admin_passkey_challenges`: a row is written whenever a sign-in or registration
ceremony starts and deleted only when one completes, so every browser prompt
somebody dismisses leaves one behind, and the table grows in ordinary use.

The Helm chart runs it as a CronJob at 03:17 daily in the cluster's timezone -
UTC unless the control plane says otherwise, since the chart sets no `timeZone` -
which `signet.sweep.enabled` turns off and `signet.sweep.schedule` moves.
Elsewhere, run it on whatever scheduler the deployment has:

```sh
SIGNET_DATABASE_OWNER_URL=postgres://signet:...@db:5432/signet \
  node dist/index.js sweep
```

It writes two lines and nothing else - the role it verified, and what each table
gave up:

```json
{ "message": "signet.sweep.identity-verified", "role": "signet" }
{ "message": "signet.sweep.completed", "deleted": 412, "launchContexts": 3, ... }
```

**Given the serving role it refuses rather than running.** Every count would come
back zero, which is indistinguishable from a database with nothing to reclaim, so
a job configured that way would report success nightly while the tables it was
meant to be trimming grew. The command observes the role it was actually given -
the same observation the server makes at startup, read the other way round - and
exits non-zero naming the role and the remedy. Ownership is not enough on its own:
where the policies were installed with `force`, which binds the owner too, the
sweep needs a role holding `BYPASSRLS` and refuses anything less.

Access token records lag behind the rest. They are a revocation list rather than
runtime state: an introspection arriving a moment after a token expired should be
answered with `active: false` and the token's metadata rather than as an unknown
token, and a resource server's clock may be behind Signet's. So their cut-off is
`SIGNET_SWEEP_ACCESS_TOKEN_GRACE` behind the present, defaulting to `24h`.

## Passkeys on console accounts

A console user may register up to ten WebAuthn passkeys and thereafter sign in with
one gesture - no email, password or verification code typed. The password stays
mandatory on every account: it is the fallback, and it is what gates every change to
the passkey list, so no passkey can lock anybody out.

### What is stored, and why none of it is encrypted

`admin_passkeys` holds the credential identifier, the COSE public key, a signature
counter, the transports the browser reported and a name, all in the clear. That is
the first stored credential material in Signet that is neither hashed nor encrypted,
and it is deliberate rather than an oversight of the hash-or-encrypt rule: a WebAuthn
public key is not a secret. Possessing it grants nothing - the private half never
leaves the authenticator - hashing it would make verification impossible, and
encrypting it would spend the master key on material the browser hands to anybody who
asks. `admin_passkey_challenges` holds short-lived random values that are deleted the
moment they are used.

Neither table carries a tenant isolation policy. Both hang off `admin_users`, which
the schema already treats as a person rather than a tenant's property, and a sign-in
challenge belongs to nobody at all until the assertion names an account. They are
listed in `RLS_EXEMPT_TABLES` with those reasons, and a test fails if a new table is
neither covered nor listed.

### The relying party comes from `SIGNET_PUBLIC_URL`

The RP ID is that URL's hostname and the expected origin is its origin. Nothing is
read from a request header, deliberately: a `Host`-derived RP ID would let a misrouted
request bind credentials to an identity the operator did not choose, and the origin
check is the whole of the phishing resistance a passkey buys.

Two consequences for a deployment:

- **Changing `SIGNET_PUBLIC_URL`'s hostname invalidates every registered passkey.**
  The credentials are scoped to the old hostname and the browser will not offer them
  for the new one. Everybody signs in with their password and registers again. A
  change of scheme or port does not, since neither is part of the RP ID - but the
  origin check will refuse a ceremony from the wrong one.
- **Passkeys need a secure context.** Browsers offer them over HTTPS, and on
  `localhost` for development. Production already requires HTTPS for the session
  cookie, so this adds no new requirement; a deployment served over plain HTTP simply
  never shows the passkey button, and the password form is unaffected.

### Removing a credential for somebody who is locked out

The console has no cross-user passkey management, deliberately: a passkey is managed
by the person who owns it, from inside their own session. An operator dealing with a
departed colleague, or somebody who has lost the only device they registered, does it
against the database as the serving role:

```sql
-- What the account holds, so the right row is removed.
select p.id, p.name, p.created_at, p.last_used_at
from admin_passkeys p
join admin_users u on u.id = p.admin_user_id
where lower(u.email) = lower('person@example.org');

-- Remove one.
delete from admin_passkeys where id = '<the id above>';
```

Removing a passkey never locks anybody out - the password still signs them in - so
this is safe to do without warning the person first. Deleting or disabling the account
itself removes its passkeys with it, by cascade.

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
helm install signet deploy/helm/signet \
  --set signet.config.SIGNET_PUBLIC_URL=https://signet.example.org
```

That brings up Signet with a bundled PostgreSQL, which is for evaluation. For
production, point at a managed instance and supply all three secrets from
outside the chart. Two database URLs, because a deployment runs two database
identities - see the tenant isolation section above for the statements that
create the serving role:

```sh
kubectl create secret generic signet-db --from-literal=url='postgres://…'
kubectl create secret generic signet-db-owner --from-literal=ownerUrl='postgres://…'
kubectl create secret generic signet-master-key --from-literal=masterKey='…'

helm install signet deploy/helm/signet \
  --set signet.postgres.enabled=false \
  --set signet.database.existingSecret=signet-db \
  --set signet.database.ownerExistingSecret=signet-db-owner \
  --set signet.masterKey.existingSecret=signet-master-key \
  --set signet.config.SIGNET_PUBLIC_URL=https://signet.example.org
```

Every value is documented in `deploy/helm/signet/README.md`. What the chart does
that is worth knowing:

- **Migrations run as a hook**, before new pods roll out. An upgrade whose
  migration fails does not replace the running pods. The exception is the first
  install with the bundled PostgreSQL, where the database is created in the same
  operation and the migration runs after it; the server's pods fail readiness
  until it has.
- **Probes are separate.** `/healthz` is liveness and answers from the process
  alone; `/readyz` is readiness and consults the database, so a pod that has lost
  its connection is taken out of the load balancer rather than restarted.
- **The root filesystem is read-only** and the container runs unprivileged, with
  `/tmp` mounted as the one writable path, and no service account token is
  mounted.
- **Replicas spread across nodes** by default, and a PodDisruptionBudget keeps one
  available through a drain. An authorization server that is down takes every app
  in front of it with it.
- **Autoscaling is off by default.** Turn it on with
  `signet.autoscaling.enabled=true`; the defaults scale on CPU between two and
  ten replicas.
- **Resource requests and limits are unset by default**, which leaves the pods in
  the BestEffort QoS class. Set `signet.resources` on any cluster with contention
  on it.
- **The chart ships no Ingress.** What belongs there is specific to the cluster,
  and the next section is what it has to do.

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
