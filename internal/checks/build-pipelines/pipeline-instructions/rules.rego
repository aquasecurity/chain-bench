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

is_pipeline_scaning_tasks_missing {
	count({job | job := input.Pipelines[_].jobs[_]; does_job_contain_one_of_tasks(job, constsLib.pipeline_vulnerability_scan_tasks)}) == 0
}

is_repository_scanning_tasks_missing {
	count({job | job := input.Pipelines[_].jobs[_]; does_job_contain_one_of_tasks(job, constsLib.secret_scan_tasks)}) == 0
	count({job | job := input.Pipelines[_].jobs[_]; does_job_contain_one_of_shell_commands(job, secret_scan_commands)}) == 0
}

is_build_job_missing {
	count({job | job := input.Pipelines[_].jobs[_]; job.metadata.build == true}) == 0
}

# In case pipelines weren't fetched
CbPolicy[msg] {
	utilsLib.is_pipelines_data_missing
	msg = {"ids": pipelineRuleIds, "status": constsLib.status.Unknown}
}

# In case there are no pipelines
CbPolicy[msg] {
	not utilsLib.is_pipelines_data_missing
	utilsLib.is_pipelines_list_empty
	msg = {"ids": pipelineRuleIds, "status": constsLib.status.Unknown, "details": constsLib.details.pipeline_no_pipelines_found}
}

# There is no build job
CbPolicy[msg] {
	not utilsLib.is_pipelines_data_missing
	not utilsLib.is_pipelines_list_empty
	is_build_job_missing
	msg := {"ids": ["2.3.1"], "status": constsLib.status.Failed, "details": constsLib.details.pipeline_no_build_job}
}

# In case organization is not fetched
CbPolicy[msg] {
	utilsLib.is_organization_data_missing
	msg = {"ids": ["2.3.5"], "status": constsLib.status.Unknown, "details": "Organization is not fetched"}
}

# In case oraganization default permissions weren't fetched
CbPolicy[msg] {
	not utilsLib.is_organization_data_missing
	permissionsLib.is_missing_org_settings_permission
	msg = {"ids": ["2.3.5"], "status": constsLib.status.Unknown, "details": "Organization is missing minimal permissions"}
}

# In case organzation default permissions are too permissive
CbPolicy[msg] {
	not utilsLib.is_organization_data_missing
	not permissionsLib.is_org_default_permission_strict
	msg = {"ids": ["2.3.5"], "status": constsLib.status.Failed, "details": constsLib.details.organization_premissive_default_repository_permissions}
}

# Looking for a pipeline that scans for vulnerabilities
CbPolicy[msg] {
	not utilsLib.is_pipelines_data_missing
	not utilsLib.is_pipelines_list_empty
	is_pipeline_scaning_tasks_missing
	msg = {"ids": ["2.3.7"], "status": constsLib.status.Failed, "details": constsLib.details.pipeline_pipelines_not_scanned_for_vulnerabilities}
}

# Looking for a pipelinethat scans for secrets
CbPolicy[msg] {
	not utilsLib.is_pipelines_data_missing
	not utilsLib.is_pipelines_list_empty
	is_repository_scanning_tasks_missing
	msg = {"ids": ["2.3.8"], "status": constsLib.status.Failed, "details": "Repository is not scanned for secrets"}
}
