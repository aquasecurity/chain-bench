package main

import data.common.consts as constsLib
import data.common.permissions as permissionsLib
import data.generic.utils as utilsLib
import future.keywords.in

pipelineRuleIds = [
	"2.3.1",
	"2.3.7",
	"2.3.8",
]

pipeline_vulnerability_scan_tasks = ["argonsecurity/scanner-action", "aquasecurity/trivy-action"]

secret_scan_tasks = [
	"argonsecurity/scanner-action",
	"zricethezav/gitleaks-action",
	"ShiftLeftSecurity/scan-action",
]

secret_scan_commands = [
	`spectral.* scan`,
	`git secrets --scan`,
	`whispers`,
	`docker run.* abhartiya/tools_gitallsecrets`,
	`detect-secrets.* scan`,
]

does_job_contain_one_of_tasks(job, regexes) {
	job.steps[i].type == "task"
	regex.match(regexes[_], job.steps[i].task.name)
}

does_job_contain_one_of_shell_commands(job, regexes) {
	job.steps[i].type == "shell"
	r := regexes[_]
	regex.match(r, job.steps[i].shell.script)
}

ensure_organization_fetched {
	input.Organization != null
}

# In case pipelines weren't fetched
CbPolicy[msg] {
	not utilsLib.ensure_pipelines_fetched
	msg = {"ids": pipelineRuleIds, "status": constsLib.status.Unknown}
}

# In case there are no pipelines
CbPolicy[msg] {
	utilsLib.ensure_pipelines_fetched
	not utilsLib.ensure_pipelines_exists
	msg = {"ids": pipelineRuleIds, "status": constsLib.status.Unknown, "details": "No pipelines were found"}
}

# There is no build job
CbPolicy[msg] {
	utilsLib.ensure_pipelines_fetched
	utilsLib.ensure_pipelines_exists
	count({job | job := input.Pipelines[_].jobs[_]; job.metadata.build == true}) == 0
	msg := {"ids": ["2.3.1"], "status": constsLib.status.Failed, "details": "No build job was found in pipelines"}
}

# In case organization is not fetched
CbPolicy[msg] {
	not ensure_organization_fetched
	msg = {"ids": ["2.3.5"], "status": constsLib.status.Unknown, "details": "Organization is not fetched"}
}

# In case oraganization default permissions weren't fetched
CbPolicy[msg] {
	ensure_organization_fetched
	permissionsLib.is_missing_org_settings_permission
	msg = {"ids": ["2.3.5"], "status": constsLib.status.Unknown, "details": "Organization is missing minimal permissions"}
}

# In case organzation default permissions are too permissive
CbPolicy[msg] {
	ensure_organization_fetched
	not permissionsLib.is_org_default_permission_strict
	msg = {"ids": ["2.3.5"], "status": constsLib.status.Failed, "details": "Organization default permissions are too permissive"}
}

# Looking for a pipeline that scans for vulnerabilities
CbPolicy[msg] {
	utilsLib.ensure_pipelines_fetched
	utilsLib.ensure_pipelines_exists
	count({job | job := input.Pipelines[_].jobs[_]; does_job_contain_one_of_tasks(job, pipeline_vulnerability_scan_tasks)}) == 0
	msg = {"ids": ["2.3.7"], "status": constsLib.status.Failed, "details": "Pipelines are not scanned for vulnerabilities"}
}

# Looking for a pipelinethat scans for secrets
CbPolicy[msg] {
	utilsLib.ensure_pipelines_fetched
	utilsLib.ensure_pipelines_exists
	count({job | job := input.Pipelines[_].jobs[_]; does_job_contain_one_of_tasks(job, secret_scan_tasks)}) == 0
	count({job | job := input.Pipelines[_].jobs[_]; does_job_contain_one_of_shell_commands(job, secret_scan_commands)}) == 0

	msg = {"ids": ["2.3.8"], "status": constsLib.status.Failed, "details": "Repository is not scanned for secrets"}
}
