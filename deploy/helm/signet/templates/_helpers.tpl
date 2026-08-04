{{/* Chart name, overridable. */}}
{{- define "signet.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified release name. */}}
{{- define "signet.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "signet.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "signet.labels" -}}
helm.sh/chart: {{ include "signet.chart" . }}
{{ include "signet.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "signet.selectorLabels" -}}
app.kubernetes.io/name: {{ include "signet.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "signet.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "signet.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "signet.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{/* Name of the secret holding the bundled subchart's user password. */}}
{{- define "signet.postgresqlSecretName" -}}
{{- .Values.postgresql.auth.existingSecret | default (printf "%s-postgresql" .Release.Name) -}}
{{- end -}}

{{/*
The serving identity's environment, shared by the server Deployment and the
migration Job so the two can never disagree about which database they are pointed
at, or about which role the server will connect as.

This is the *non-owning* role. Postgres exempts a table's owner from that table's
row-level security policies, so the server has to connect as a role that owns
nothing, and `signet.migrationEnv` below is the only place the owning identity
appears. The server refuses to start if the role it is given turns out to be
exempt after all - see `apps/server/src/enforcement.ts` - so a chart that got this
wrong would fail its rollout rather than serve unprotected.

The migration Job reads this too, but for the role *name* alone: it grants that
role the access the server needs, and never uses its password.

When the bundled PostgreSQL subchart is enabled, the password is read from the
subchart's own secret and the connection URL is composed by the server from
discrete parts. Generating a password here instead would produce a value that
does not match the one the subchart actually set on the database.
*/}}
{{- define "signet.env" -}}
- name: PORT
  value: {{ .Values.service.targetPort | quote }}
- name: SIGNET_PUBLIC_URL
  value: {{ .Values.publicUrl | quote }}
- name: SIGNET_LOG_LEVEL
  value: {{ .Values.logLevel | quote }}
{{- if .Values.postgresql.enabled }}
- name: SIGNET_DATABASE_HOST
  value: {{ printf "%s-postgresql" .Release.Name | quote }}
- name: SIGNET_DATABASE_PORT
  value: "5432"
- name: SIGNET_DATABASE_NAME
  value: {{ .Values.postgresql.auth.database | quote }}
- name: SIGNET_DATABASE_USER
  value: {{ .Values.postgresql.auth.username | quote }}
- name: SIGNET_DATABASE_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "signet.postgresqlSecretName" . }}
      key: password
{{- else }}
- name: SIGNET_DATABASE_URL
  valueFrom:
    secretKeyRef:
{{- if .Values.database.existingSecret }}
      name: {{ .Values.database.existingSecret }}
      key: {{ .Values.database.existingSecretKey }}
{{- else }}
      name: {{ include "signet.fullname" . }}-db
      key: url
{{- end }}
{{- end }}
- name: SIGNET_MASTER_KEY
  valueFrom:
    secretKeyRef:
{{- if .Values.masterKey.existingSecret }}
      name: {{ .Values.masterKey.existingSecret }}
      key: {{ .Values.masterKey.existingSecretKey }}
{{- else }}
      name: {{ include "signet.fullname" . }}-master-key
      key: masterKey
{{- end }}
{{- with .Values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
The migration Job's environment: the serving identity's, plus the owning one.

`migrate` is the only command that needs the owner credential, and this is the only
template that supplies it. Migrations are DDL, and the grants that follow them must
be issued by the role that owns the objects being granted - so the credential
exists at one point in a deployment's life rather than sitting in the running pod
for its lifetime.

With the bundled subchart, the two identities already exist and no role has to be
created: the subchart's superuser owns whatever the migrations create, and its
custom user - `postgresql.auth.username`, which the server connects as - owns
nothing and is therefore bound by the policies. The URL is composed from the
password using Kubernetes' dependent-variable expansion, which substitutes a
`$(VAR)` naming an earlier entry in the same container's `env`. That expects a
URL-safe password: the subchart generates an alphanumeric one, and an operator
supplying their own with reserved characters in it should pass a complete URL
through `database.ownerExistingSecret` instead.
*/}}
{{- define "signet.migrationEnv" -}}
{{ include "signet.env" . }}
{{- if .Values.postgresql.enabled }}
- name: SIGNET_DATABASE_OWNER_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "signet.postgresqlSecretName" . }}
      key: postgres-password
- name: SIGNET_DATABASE_OWNER_URL
  value: {{ printf "postgres://postgres:$(SIGNET_DATABASE_OWNER_PASSWORD)@%s-postgresql:5432/%s" .Release.Name .Values.postgresql.auth.database | quote }}
{{- else }}
- name: SIGNET_DATABASE_OWNER_URL
  valueFrom:
    secretKeyRef:
{{- if .Values.database.ownerExistingSecret }}
      name: {{ .Values.database.ownerExistingSecret }}
      key: {{ .Values.database.ownerExistingSecretKey }}
{{- else }}
      name: {{ include "signet.fullname" . }}-db-owner
      key: ownerUrl
{{- end }}
{{- end }}
{{- end -}}
