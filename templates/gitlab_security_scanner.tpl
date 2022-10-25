{
  "version": "14.1.4",
  "scan":{
    "scanner":{
        "id":"chain-bench",
        "name":"Supply chain Scanner",
        "vendor": {
            "name":"chain-bench"
        },
        "version":"1.0"
      },
    "start_time":"2022-04-07T12:26:58",
    "end_time":"2022-04-26T12:26:00",
    "status":"success",
    "messages": [
      ],
    "type":"container_scanning"
  },
  "vulnerabilities": [
  {{- $t_first := true }}
  {{- range . }}
     {{- if eq .Result "Failed"}}
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
        "severity": {{ .Severity | printf "%q" }},
        "confidence": "Unknown",
        "solution": {{ .Remediation | printf "%q" }},
        "scanner": {
          "id": "chain-bench",
          "name": "chain-bench",
          "vendor": {
           "name":"chain-bench"
          }
        },
        "location": {
          "dependency": {
            "package": {
              "name": "{{ .ID }}"
            },
            "version": "0.1.3"
          },
          "operating_system": "Unknown",
          "image": "{{ "Supply Chain Scanner" }}"
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