# Signet

Deploys [Signet](../../../README.md), a multi-tenant SMART App Launch
authorization server, on Kubernetes.

The chart installs the server as a Deployment behind a ClusterIP Service,
applies database migrations as a Helm hook Job before new pods roll out, sweeps
expired rows nightly as a CronJob, and optionally brings up a PostgreSQL for
evaluation.

Signet is experimental software and must not be used to protect sensitive data.
See the disclaimer in the [project README](../../../README.md).

## Features

- **Two database identities, kept apart.** Signet connects as a role that owns
  none of its tables, because PostgreSQL exempts a table's owner from that
  table's row-level security policies. The owning identity reaches the migration
  Job and the sweep CronJob alone - the two things that must act outside a single
  tenant - and never the server's pods, which
  `scripts/checkChartCredentials.mjs` asserts against the chart's rendered
  output.
- **The expiry sweep on a schedule.** Passkey ceremony challenges accumulate in
  ordinary use, so a nightly CronJob deletes every runtime row that has passed
  its expiry. Given the wrong credential the command refuses rather than
  reporting a database it cannot see as clean.
- **Migrations as a hook.** An upgrade whose migration fails does not replace
  the running pods.
- **Separate liveness and readiness.** `/healthz` answers from the process
  alone; `/readyz` consults the database, so a pod that has lost its connection
  leaves the load balancer rather than restarting.
- **Unprivileged, read-only root filesystem**, with `/tmp` as the one writable
  path and no service account token mounted.
- **Spread across nodes** by default, with a PodDisruptionBudget that keeps one
  replica through a drain.
- **Generated secrets that survive an upgrade.** The signing-key envelope key
  and the bundled database's passwords are generated on install and read back
  from the cluster on every upgrade, so neither is replaced underneath the data
  it protects.
- **A bundled PostgreSQL**, off with one value, for evaluation and
  connectathons.

## Prerequisites

- Kubernetes 1.23 or later (the chart uses `autoscaling/v2` and `policy/v1`).
- Helm 3.8 or later.
- An ingress, gateway or load balancer terminating TLS in front of the Service.
  The chart deliberately ships no Ingress: what belongs there is specific to the
  cluster. Signet reads `X-Forwarded-For` for the audit trail and for rate-limit
  keys, so whatever sits in front of it must overwrite an inbound value rather
  than pass it through.
- A `SIGNET_MASTER_KEY` you can back up, for anything beyond evaluation.

## Installation

Evaluation, with the bundled database:

```bash
helm install signet deploy/helm/signet \
  --set signet.config.SIGNET_PUBLIC_URL=https://signet.example.org
```

Against a managed database. Both identities are supplied from outside the chart,
and the two URLs must name different roles - `migrate` refuses two URLs naming
the same one, because that deployment could not enforce tenant isolation:

```bash
kubectl create secret generic signet-db \
  --from-literal=url='postgres://signet_app:…@db.example.org:5432/signet'
kubectl create secret generic signet-db-owner \
  --from-literal=ownerUrl='postgres://signet:…@db.example.org:5432/signet'
kubectl create secret generic signet-master-key \
  --from-literal=masterKey='…'

helm install signet deploy/helm/signet \
  --set signet.postgres.enabled=false \
  --set signet.database.existingSecret=signet-db \
  --set signet.database.ownerExistingSecret=signet-db-owner \
  --set signet.masterKey.existingSecret=signet-master-key \
  --set signet.config.SIGNET_PUBLIC_URL=https://signet.example.org
```

Creating the serving role on a managed instance is two statements; see the
tenant isolation section of [docs/operations.md](../../../docs/operations.md).

## Configuration

| Parameter                                           | Description                                                                                           | Default                                 |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | --------------------------------------- |
| `signet.image`                                      | Container image to run.                                                                               | `ghcr.io/aehrc/signet:1.0.0`            |
| `signet.imagePullPolicy`                            | Image pull policy for the server and migration Job.                                                   | `Always`                                |
| `signet.imagePullSecrets`                           | Secrets used to pull the image.                                                                       | `[]`                                    |
| `signet.replicas`                                   | Server replicas, ignored when autoscaling is on.                                                      | `2`                                     |
| `signet.config`                                     | Non-sensitive environment for the server and migration Job.                                           | `SIGNET_PUBLIC_URL`, `SIGNET_LOG_LEVEL` |
| `signet.secretConfig`                               | Sensitive environment, written to a Secret and mounted by reference.                                  | `{}`                                    |
| `signet.masterKey.existingSecret`                   | Secret holding the signing-key envelope key. Generated when unset.                                    | `~`                                     |
| `signet.masterKey.existingSecretKey`                | Key within that secret.                                                                               | `masterKey`                             |
| `signet.masterKey.value`                            | Envelope key supplied inline. For evaluation only.                                                    | `~`                                     |
| `signet.database.existingSecret`                    | Secret holding the serving role's connection URL.                                                     | `~`                                     |
| `signet.database.existingSecretKey`                 | Key within that secret.                                                                               | `url`                                   |
| `signet.database.url`                               | Serving role's connection URL, written to a chart-created Secret.                                     | `~`                                     |
| `signet.database.ownerExistingSecret`               | Secret holding the owning identity's connection URL, read by the migration Job and the sweep CronJob. | `~`                                     |
| `signet.database.ownerExistingSecretKey`            | Key within that secret.                                                                               | `ownerUrl`                              |
| `signet.database.ownerUrl`                          | Owning identity's connection URL, written to a chart-created Secret.                                  | `~`                                     |
| `signet.migrations.enabled`                         | Run migrations as a Helm hook Job.                                                                    | `true`                                  |
| `signet.migrations.backoffLimit`                    | Retries before the migration Job fails.                                                               | `3`                                     |
| `signet.migrations.activeDeadlineSeconds`           | Wall-clock limit on the migration Job.                                                                | `600`                                   |
| `signet.sweep.enabled`                              | Delete expired runtime rows nightly, as a CronJob.                                                    | `true`                                  |
| `signet.sweep.schedule`                             | Cron schedule for the sweep.                                                                          | `17 3 * * *`                            |
| `signet.sweep.accessTokenGrace`                     | How far the access token cut-off lags the present, as `24h`, `30m` or `7d`.                           | `24h`                                   |
| `signet.sweep.backoffLimit`                         | Retries before a sweep Job fails.                                                                     | `3`                                     |
| `signet.sweep.activeDeadlineSeconds`                | Wall-clock limit on a sweep Job.                                                                      | `900`                                   |
| `signet.sweep.startingDeadlineSeconds`              | How late a missed sweep may still start.                                                              | `300`                                   |
| `signet.sweep.successfulJobsHistoryLimit`           | Completed sweep Jobs kept.                                                                            | `3`                                     |
| `signet.sweep.failedJobsHistoryLimit`               | Failed sweep Jobs kept.                                                                               | `3`                                     |
| `signet.service.type`                               | Service type.                                                                                         | `ClusterIP`                             |
| `signet.service.port`                               | Port the Service listens on.                                                                          | `80`                                    |
| `signet.service.targetPort`                         | Port the container listens on, passed to the process as `PORT`.                                       | `3000`                                  |
| `signet.service.annotations`                        | Annotations on the Service.                                                                           | `{}`                                    |
| `signet.resources`                                  | Resource requests and limits for the server and migration containers.                                 | `{}`                                    |
| `signet.autoscaling.enabled`                        | Create a HorizontalPodAutoscaler.                                                                     | `false`                                 |
| `signet.autoscaling.minReplicas`                    | Lower bound on replicas.                                                                              | `2`                                     |
| `signet.autoscaling.maxReplicas`                    | Upper bound on replicas.                                                                              | `10`                                    |
| `signet.autoscaling.targetCPUUtilizationPercentage` | CPU utilisation the autoscaler targets.                                                               | `70`                                    |
| `signet.podDisruptionBudget.enabled`                | Create a PodDisruptionBudget.                                                                         | `true`                                  |
| `signet.podDisruptionBudget.minAvailable`           | Replicas that must stay available through a drain.                                                    | `1`                                     |
| `signet.podAnnotations`                             | Extra annotations on the server's pods.                                                               | `{}`                                    |
| `signet.podLabels`                                  | Extra labels on the server's pods.                                                                    | `{}`                                    |
| `signet.podSecurityContext`                         | Pod-level security context for the server and migration Job.                                          | unprivileged uid 1000                   |
| `signet.securityContext`                            | Container-level security context for the server and migration Job.                                    | no escalation, read-only root           |
| `signet.terminationGracePeriodSeconds`              | Grace period for a shutting-down pod.                                                                 | `30`                                    |
| `signet.nodeSelector`                               | Node selector for the server and migration Job.                                                       | `{}`                                    |
| `signet.tolerations`                                | Tolerations for the server and migration Job.                                                         | `[]`                                    |
| `signet.affinity`                                   | Affinity rules for the server and migration Job.                                                      | `{}`                                    |
| `signet.topologySpreadConstraints`                  | Spread constraints for the server's pods; the chart adds the label selector.                          | one per hostname, `ScheduleAnyway`      |
| `signet.postgres.enabled`                           | Bring up the bundled PostgreSQL.                                                                      | `true`                                  |
| `signet.postgres.image`                             | PostgreSQL image.                                                                                     | `postgres:18-alpine`                    |
| `signet.postgres.imagePullPolicy`                   | Image pull policy for PostgreSQL.                                                                     | `Always`                                |
| `signet.postgres.database`                          | Database created on first initialisation.                                                             | `signet`                                |
| `signet.postgres.owner`                             | Superuser that owns the schema and applies migrations.                                                | `signet`                                |
| `signet.postgres.ownerPassword`                     | Its password. Generated when unset.                                                                   | `~`                                     |
| `signet.postgres.servingRole`                       | Non-owning role the server connects as.                                                               | `signet_app`                            |
| `signet.postgres.servingPassword`                   | Its password. Generated when unset.                                                                   | `~`                                     |
| `signet.postgres.resources`                         | Resource requests and limits for PostgreSQL.                                                          | `{}`                                    |
| `signet.postgres.persistence.enabled`               | Claim a volume. When false the database is lost with the pod.                                         | `true`                                  |
| `signet.postgres.persistence.size`                  | Size of the claim.                                                                                    | `8Gi`                                   |
| `signet.postgres.persistence.storageClassName`      | Storage class of the claim. Cluster default when unset.                                               | `~`                                     |
| `signet.postgres.podSecurityContext`                | Pod-level security context for PostgreSQL.                                                            | unprivileged uid 70                     |
| `signet.postgres.securityContext`                   | Container-level security context for PostgreSQL.                                                      | no escalation                           |
| `signet.postgres.nodeSelector`                      | Node selector for PostgreSQL.                                                                         | `{}`                                    |
| `signet.postgres.tolerations`                       | Tolerations for PostgreSQL.                                                                           | `[]`                                    |
| `signet.postgres.affinity`                          | Affinity rules for PostgreSQL.                                                                        | `{}`                                    |

### Configuration and secrets

Anything Signet reads from the environment goes in `config`, and anything
sensitive goes in `secretConfig`, which the chart writes to a Secret and mounts
by reference. Both reach the server and the migration Job. A name set in both
takes its value from `config`: Kubernetes lets a container's `env` override its
`envFrom`.

```yaml
signet:
  config:
    SIGNET_PUBLIC_URL: "https://signet.example.org"
    SIGNET_LOG_LEVEL: "warn"
    SIGNET_ACCESS_TOKEN_TTL: "1800"

  secretConfig:
    SIGNET_SMTP_PASSWORD: "…"
```

The database URLs and the signing-key envelope key are not part of this. They
have their own values, because the chart has to know which pod spec each one is
mounted into.

## Examples

### Resource requests and limits

Unset by default, which leaves the pods in the BestEffort QoS class. A cluster
with contention on it wants something like:

```yaml
signet:
  resources:
    requests:
      cpu: "100m"
      memory: "256Mi"
    limits:
      cpu: "1"
      memory: "512Mi"
```

### Autoscaling

```yaml
signet:
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 20
    targetCPUUtilizationPercentage: 60
```

Rate limiting is per process, so `n` replicas make the effective limit up to `n`
times what is configured. It is there to defeat online guessing, which a small
integer factor does not rescue; a deployment needing an exact global limit
should set one at the ingress.

### An ephemeral database for a demonstration

```yaml
signet:
  replicas: 1
  podDisruptionBudget:
    enabled: false
  postgres:
    persistence:
      enabled: false
```

### Bringing your own signing-key envelope key

```bash
kubectl create secret generic signet-master-key \
  --from-literal=masterKey="$(openssl rand -base64 32)"
```

```yaml
signet:
  masterKey:
    existingSecret: "signet-master-key"
    existingSecretKey: "masterKey"
```

Left unset, the chart generates one, annotates it `helm.sh/resource-policy:
keep`, and reads it back from the cluster on each upgrade rather than generating
another. Back it up somewhere other than the database it protects: if it is
lost, every stored endpoint signing key becomes undecryptable and every client
must be re-registered.

## Upgrading

Migrations run before new pods roll out, as a `pre-upgrade` hook. An upgrade
whose migration fails leaves the running pods in place.

Two things the chart reads back from the cluster instead of regenerating: the
signing-key envelope key, and the bundled database's passwords. Both are
therefore stable across `helm upgrade`, and both are rendered as fresh random
values by `helm template`, which has no cluster to read.

Watch it:

```bash
kubectl rollout status deployment/signet-deployment
```

### From chart 0.1.x

0.2.0 renames every value and every resource, so an upgrade in place is not
possible. Uninstall, then install afresh with the new values.

- All values moved under a top-level `signet` key.
- `publicUrl` and `logLevel` became entries in `signet.config`, and `extraEnv`
  became the rest of it.
- The bundled database moved from the Bitnami `postgresql` subchart to a
  StatefulSet over the official `postgres` image, under `signet.postgres`. Its
  data is not portable between the two.
- `replicaCount` became `signet.replicas`; `image.repository` and `image.tag`
  became the single string `signet.image`.
- The Ingress was removed. Bring your own.
- The ServiceAccount was removed: Signet does not call the Kubernetes API, and
  its pods now mount no token at all.
- Resources are unset by default rather than requested and limited.

## Uninstalling

```bash
helm uninstall signet
```

Three things are deliberately left behind, because losing them loses data:

```bash
kubectl delete secret signet-master-key signet-postgres-secret
kubectl delete pvc data-signet-postgres-0
```

## Compatibility

| Chart version | App version | Kubernetes |
| ------------- | ----------- | ---------- |
| 1.0.0         | 1.0.0       | 1.23+      |
| 0.2.0         | 0.1.0       | 1.23+      |
| 0.1.0         | 0.1.0       | 1.23+      |
