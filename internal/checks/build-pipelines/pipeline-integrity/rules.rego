package main

import data.common.consts as constsLib
import data.generic.utils as utilsLib
import future.keywords.in

ruleIds = [
	"2.4.2",
	"2.4.6",
]

sbom_tasks = [
	`argonsecurity/actions/generate-manifest`,
	`anchore/sbom-action`,
	`CycloneDX/gh-\w+-generate-sbom`,
]

sbom_generation_commands = [
	`billy generate`,
	`trivy sbom`,
	`trivy .* --format cyclonedx`,
	`syft .*`,
	`spdx-sbom-generator`,
	`cyclonedx-\w+`,
	`jake sbom`,
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

is_task_version_pinned(step) {
	step.type == "task"
	step.task.version_type != "commit"
}

is_all_tasks_pinned[unpinnedtaskCount] {
	unpinnedtaskCount = count({step |
		step = input.Pipelines[_].jobs[_].steps[_]
		is_task_version_pinned(step)
	})

	unpinnedtaskCount > 0
}

are_there_pipelines_without_sbom[pipelinesWithoutSBOM] {
	pipelinesWithoutSBOM := count({i |
		input.Pipelines[i].jobs[j].metadata.build == true
		job := input.Pipelines[i].jobs[j]
		not does_job_contain_one_of_tasks(job, sbom_tasks)
		not does_job_contain_one_of_shell_commands(job, sbom_generation_commands)
	})

	pipelinesWithoutSBOM > 0
}

# In case pipelines weren't fetched
CbPolicy[msg] {
	utilsLib.is_pipelines_data_missing
	msg = {"ids": ruleIds, "status": constsLib.status.Unknown}
}

# In case there are no pipelines
CbPolicy[msg] {
	not utilsLib.is_pipelines_data_missing
	utilsLib.is_pipelines_list_empty
	msg = {"ids": ruleIds, "status": constsLib.status.Unknown, "details": constsLib.details_pipeline_noPipelinesFound}
}

# Looking for tasks that are not pinned
CbPolicy[msg] {
	not utilsLib.is_pipelines_data_missing
	unpinnedtaskCount := is_all_tasks_pinned[i]
	details := sprintf("%v task(s) are not pinned", [unpinnedtaskCount])
	msg := {"ids": ["2.4.2"], "status": constsLib.status.Failed, "details": details}
}

# Looking for build jobs with an SBOM
CbPolicy[msg] {
	not utilsLib.is_pipelines_data_missing
	pipelinesWithoutSBOM := are_there_pipelines_without_sbom[i]
	details := sprintf("%v pipeline(s) contain a build job without SBOM generation", [pipelinesWithoutSBOM])
	msg = {"ids": ["2.4.6"], "status": constsLib.status.Failed, "details": details}
}
