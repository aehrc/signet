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
Environment shared by the server Deployment and the migration Job, so the two
can never disagree about which database they are pointed at.

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
