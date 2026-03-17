{{- define "secrets.configureEnv" -}}
{{- $env := list -}}

{{- $grpcAddress := trimAll " \n\t" (default ":50051" .Values.secrets.grpcAddress) -}}
{{- if $grpcAddress }}
{{- $env = append $env (dict "name" "GRPC_ADDRESS" "value" $grpcAddress) -}}
{{- end }}

{{- $dbSecret := trim (default "" .Values.secrets.databaseUrl.existingSecret) -}}
{{- $dbVar := dict "name" "DATABASE_URL" -}}
{{- if $dbSecret }}
  {{- $dbKey := default "database-url" .Values.secrets.databaseUrl.existingSecretKey -}}
  {{- $_ := set $dbVar "valueFrom" (dict "secretKeyRef" (dict "name" $dbSecret "key" $dbKey)) -}}
{{- else }}
  {{- $dbValue := required "secrets.databaseUrl.value is required" (trimAll " \n\t" (default "" .Values.secrets.databaseUrl.value)) -}}
  {{- $_ := set $dbVar "value" $dbValue -}}
{{- end }}
{{- $env = append $env $dbVar -}}

{{- $userEnv := .Values.env | default (list) -}}
{{- $_ := set .Values "env" (concat $env $userEnv) -}}
{{- end -}}
