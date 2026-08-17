{{/*
Expand the name of the chart.
*/}}
{{- define "aim.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name. If the release name contains the chart name it is
used as-is (so `helm install aim .` yields resources named `aim-*`).
*/}}
{{- define "aim.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "aim.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "aim.labels" -}}
helm.sh/chart: {{ include "aim.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}

{{/*
Component selector labels. Usage:
  {{ include "aim.selectorLabels" (dict "component" "ingest" "context" .) }}
*/}}
{{- define "aim.selectorLabels" -}}
app.kubernetes.io/instance: {{ .context.Release.Name }}
app.kubernetes.io/name: {{ .component }}
{{- end }}

{{/*
Name of the secret to read credentials from (chart-generated or pre-existing).
*/}}
{{- define "aim.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- printf "%s-secrets" (include "aim.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Render an image reference: [registry/]repository:tag. Tag falls back to the
chart appVersion when empty.
*/}}
{{- define "aim.image" -}}
{{- $tag := .image.tag | default .context.Chart.AppVersion -}}
{{- if .context.Values.global.imageRegistry }}
{{- printf "%s/%s:%s" .context.Values.global.imageRegistry .image.repository $tag }}
{{- else }}
{{- printf "%s:%s" .image.repository $tag }}
{{- end }}
{{- end }}

{{/*
Pod-level security context for AIM app workloads (ingest / api / guardrail /
migrate). Intentionally NOT applied to vendor StatefulSets (postgres, minio)
whose images expect their own UIDs. See docs/deployment/helm-security-defaults-audit.md.
*/}}
{{- define "aim.appPodSecurityContext" -}}
{{- if and .Values.security .Values.security.podSecurityContext -}}
{{- toYaml .Values.security.podSecurityContext }}
{{- end -}}
{{- end }}

{{/*
Container-level security context for AIM app workloads.
Images already set USER (node / guardrail); we enforce non-root + drop ALL.
*/}}
{{- define "aim.appContainerSecurityContext" -}}
{{- if and .Values.security .Values.security.containerSecurityContext -}}
{{- toYaml .Values.security.containerSecurityContext }}
{{- end -}}
{{- end }}

{{/*
Object-store endpoint for ingest.
1. objectStore.endpoint if set (external or cross-namespace)
2. in-cluster MinIO when minio.enabled
3. fail when minio.enabled=false and no endpoint
Usage: {{ include "aim.objectStoreEndpoint" . }}
*/}}
{{- define "aim.objectStoreEndpoint" -}}
{{- $override := "" -}}
{{- if and .Values.objectStore .Values.objectStore.endpoint -}}
{{- $override = .Values.objectStore.endpoint -}}
{{- end -}}
{{- if $override -}}
{{- $override -}}
{{- else if .Values.minio.enabled -}}
{{- printf "http://%s-minio:%v" (include "aim.fullname" .) .Values.minio.service.apiPort -}}
{{- else -}}
{{- fail "minio.enabled=false requires objectStore.endpoint (e.g. https://s3.amazonaws.com)" -}}
{{- end -}}
{{- end }}

{{/*
Multi-AZ placement for app Deployments (package A).
When topology.spread.enabled, pods prefer distinct topology.kubernetes.io/zone.
When topology.antiAffinity.enabled, prefer different nodes (hostname).
Usage:
  {{- with include "aim.appPlacement" (dict "component" "api" "context" . "Values" .Values) }}
  {{- . | nindent 6 }}
  {{- end }}
*/}}
{{- define "aim.appPlacement" -}}
{{- $t := .Values.topology | default dict -}}
{{- $spread := $t.spread | default dict -}}
{{- $aa := $t.antiAffinity | default dict -}}
{{- if $spread.enabled }}
topologySpreadConstraints:
  - maxSkew: {{ $spread.maxSkew | default 1 }}
    topologyKey: {{ $spread.topologyKey | default "topology.kubernetes.io/zone" | quote }}
    whenUnsatisfiable: {{ $spread.whenUnsatisfiable | default "ScheduleAnyway" }}
    labelSelector:
      matchLabels:
        {{- include "aim.selectorLabels" (dict "component" .component "context" .context) | nindent 8 }}
{{- end }}
{{- if $aa.enabled }}
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: {{ $aa.weight | default 100 }}
        podAffinityTerm:
          topologyKey: {{ $aa.topologyKey | default "kubernetes.io/hostname" | quote }}
          labelSelector:
            matchLabels:
              {{- include "aim.selectorLabels" (dict "component" .component "context" .context) | nindent 14 }}
{{- end }}
{{- end }}
