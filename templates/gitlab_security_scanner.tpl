{
  "version": "14.0.6",
  "vulnerabilities": [
  {{- $t_first := true }}
  {{- range . }}
     {{- if and (eq .ID "1.1.4" "1.1.6" "1.1.8" "1.1.9" "1.1.10" "1.1.11" "1.1.12" "1.1.13" "1.1.16" "1.3.5" "1.3.8" )  (eq .Result "Failed")}}
      {{- if $t_first -}}
        {{- $t_first = false -}}
      {{ else -}}
        ,
      {{- end }}
      {
        "id": "{{ .ID }}",
        "category": "container_scanning",
        "message": {{ .Name | printf "%q" }},
        "description": {{ .Description | printf "%q" }},
        "cve": "{{ .ID }}",
        "severity": "Critical",
        "confidence": "Unknown",
        "solution": {{ .Remediation | printf "%q" }},
        "scanner": {
          "id": "chain-bench",
          "name": "chain-bench"
        },
        "location": {
          "dependency": {
            "package": {
              "name": "{{ .ID }}"
            },
            "version": "0.1.3"
          },
          "operating_system": "Unknown",
          "image": "{{ "myImage" }}"
        },
        "identifiers": [
          {
            "type": "cve",
            "name": "{{ .ID }}",
            "value": "{{ .ID }}",
            "url": "{{ .Url }}"
          }
        ]
      }
    {{- end }}
  {{- end }}
  ],
  "remediations": []
}