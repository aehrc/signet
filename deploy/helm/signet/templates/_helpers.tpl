{{/*
Labels applied to every resource in the chart.
*/}}
{{- define "signet.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "signet.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
The labels a Service, Deployment or PodDisruptionBudget selects the server's
pods by. Nothing that changes between revisions may appear here: a Deployment's
selector is immutable once created.
*/}}
{{- define "signet.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
The serving identity's environment, shared by the server Deployment and the
migration Job so the two can never disagree about which database they are
pointed at, or about which role the server will connect as.

This is the *non-owning* role. Postgres exempts a table's owner from that
table's row-level security policies, so the server has to connect as a role that
owns nothing, and `signet.migrationEnv` below is the only place the owning
identity appears. The server refuses to start if the role it is given turns out
to be exempt after all - see `apps/server/src/enforcement.ts` - so a chart that
got this wrong would fail its rollout rather than serve unprotected.

The migration Job reads this too, but for the role *name* alone: it grants that
role the access the server needs, and never uses its password.

With the bundled PostgreSQL, the password is read from the chart's own secret
and the connection URL is composed by the server from discrete parts, which
keeps the credential out of every rendered manifest.
*/}}
{{- define "signet.env" -}}
- name: PORT
  value: {{ .Values.signet.service.targetPort | quote }}
{{- range $name, $value := .Values.signet.config }}
- name: {{ $name }}
  value: {{ $value | quote }}
{{- end }}
{{- if .Values.signet.postgres.enabled }}
- name: SIGNET_DATABASE_HOST
  value: {{ printf "%s-postgres-service" .Release.Name | quote }}
- name: SIGNET_DATABASE_PORT
  value: "5432"
- name: SIGNET_DATABASE_NAME
  value: {{ .Values.signet.postgres.database | quote }}
- name: SIGNET_DATABASE_USER
  value: {{ .Values.signet.postgres.servingRole | quote }}
- name: SIGNET_DATABASE_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ printf "%s-postgres-secret" .Release.Name | quote }}
      key: servingPassword
{{- else }}
- name: SIGNET_DATABASE_URL
  valueFrom:
    secretKeyRef:
{{- if .Values.signet.database.existingSecret }}
      name: {{ .Values.signet.database.existingSecret | quote }}
      key: {{ .Values.signet.database.existingSecretKey | quote }}
{{- else }}
      name: {{ printf "%s-db" .Release.Name | quote }}
      key: url
{{- end }}
{{- end }}
- name: SIGNET_MASTER_KEY
  valueFrom:
    secretKeyRef:
{{- if .Values.signet.masterKey.existingSecret }}
      name: {{ .Values.signet.masterKey.existingSecret | quote }}
      key: {{ .Values.signet.masterKey.existingSecretKey | quote }}
{{- else }}
      name: {{ printf "%s-master-key" .Release.Name | quote }}
      key: masterKey
{{- end }}
{{- end -}}

{{/*
The migration Job's environment: the serving identity's, plus the owning one.

`migrate` needs both, and is the only command that does: it applies DDL as the
owner, and grants the serving role the access the server needs - which means
knowing that role's *name*, which it takes from the serving connection. It never
uses the serving password.

With the bundled PostgreSQL the two identities already exist and no role has to
be created: `postgres.owner` owns whatever the migrations create, and
`postgres.servingRole` - which the server connects as - owns nothing and is
therefore bound by the policies.

The owning half is `signet.ownerEnv` below, which the sweep CronJob takes on its
own. Those two are the only pod specs in this chart that carry it, and
`scripts/checkChartCredentials.mjs` asserts as much against the rendered output.
*/}}
{{- define "signet.migrationEnv" -}}
{{ include "signet.env" . }}{{ include "signet.ownerEnv" . }}
{{- end -}}

{{/*
The owning identity on its own, for a pod that needs it and nothing else.

The expiry sweep is that pod. It acts across tenants - which is what the serving
role must not be able to do - and it reads no other configuration at all: no
public URL, no master key, and not the serving connection either, which it would
delete nothing with. So it is given this rather than `signet.migrationEnv`, and
holds no credential it has no use for.

With the bundled PostgreSQL the URL is composed from the password using
Kubernetes' dependent-variable expansion, which substitutes a `$(VAR)` naming an
earlier entry in the same container's `env`. That expects a URL-safe password:
the chart generates an alphanumeric one, and an operator supplying their own with
reserved characters in it should point at an external database and pass a
complete URL through `database.ownerExistingSecret` instead.
*/}}
{{- define "signet.ownerEnv" -}}
{{- if .Values.signet.postgres.enabled }}
- name: SIGNET_DATABASE_OWNER_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ printf "%s-postgres-secret" .Release.Name | quote }}
      key: ownerPassword
- name: SIGNET_DATABASE_OWNER_URL
  value: {{ printf "postgres://%s:$(SIGNET_DATABASE_OWNER_PASSWORD)@%s-postgres-service:5432/%s" .Values.signet.postgres.owner .Release.Name .Values.signet.postgres.database | quote }}
{{- else }}
- name: SIGNET_DATABASE_OWNER_URL
  valueFrom:
    secretKeyRef:
{{- if .Values.signet.database.ownerExistingSecret }}
      name: {{ .Values.signet.database.ownerExistingSecret | quote }}
      key: {{ .Values.signet.database.ownerExistingSecretKey | quote }}
{{- else }}
      name: {{ printf "%s-db-owner" .Release.Name | quote }}
      key: ownerUrl
{{- end }}
{{- end }}
{{- end -}}
