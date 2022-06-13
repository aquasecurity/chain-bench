package main

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

# In case pipelines weren't fetched
CbPolicy[msg] {
	not utilsLib.ensure_pipelines_fetched
	msg = {"ids": ruleIds, "status": "Unknown"}
}

# In case there are no pipelines
CbPolicy[msg] {
	utilsLib.ensure_pipelines_fetched
	not utilsLib.ensure_pipelines_exists
	msg = {"ids": ruleIds, "status": "Unknown", "details": "No pipelines were found"}
}

# Looking for tasks that are not pinned
CbPolicy[msg] {
	utilsLib.ensure_pipelines_fetched
	unpinnedtaskCount := count({step |
		step = input.Pipelines[_].jobs[_].steps[_]
		is_task_version_pinned(step)
	})

	unpinnedtaskCount > 0
	msg := {"ids": ["2.4.2"], "status": "Failed", "details": sprintf("%v task(s) are not pinned", [unpinnedtaskCount])}
}

# Looking for build jobs with an SBOM
CbPolicy[msg] {
	utilsLib.ensure_pipelines_fetched
	pipelinesWithoutSBOM = count({i |
		input.Pipelines[i].jobs[j].metadata.build == true
		job := input.Pipelines[i].jobs[j]
		not does_job_contain_one_of_tasks(job, sbom_tasks)
		not does_job_contain_one_of_shell_commands(job, sbom_generation_commands)
	})

	pipelinesWithoutSBOM > 0
	msg = {"ids": ["2.4.6"], "status": "Failed", "details": sprintf("%v pipeline(s) contain a build job without SBOM generation", [pipelinesWithoutSBOM])}
}
