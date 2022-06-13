package main

import data.generic.utils as utilsLib
import future.keywords.in

pipeline_vulnerability_scan_tasks = ["argonsecurity/scanner-action", "aquasecurity/trivy-action"]

does_job_contain_one_of_tasks(job, regexes) {
	job.steps[i].type == "task"
	regex.match(regexes[_], job.steps[i].task.name)
}

CbPolicy[msg] {
	not utilsLib.ensure_pipelines_fetched
	msg = {"ids": ["3.2.2", "3.2.3"], "status": "Unknown"}
}

# In case there are no pipelines
CbPolicy[msg] {
	utilsLib.ensure_pipelines_fetched
	not utilsLib.ensure_pipelines_exists
	msg = {"ids": ["3.2.2", "3.2.3"], "status": "Unknown", "details": "No pipelines were found"}
}

# Looking for a pipeline that scans for vulnerabilities
CbPolicy[msg] {
	utilsLib.ensure_pipelines_fetched
	utilsLib.ensure_pipelines_exists
	count({job | job := input.Pipelines[_].jobs[_]; does_job_contain_one_of_tasks(job, pipeline_vulnerability_scan_tasks)}) == 0
	msg = {"ids": ["3.2.2"], "status": "Failed", "details": "Pipeline dependencies are not scanned for vulnerabilities"}
}

# Looking for a pipeline that scans for licenses
CbPolicy[msg] {
	utilsLib.ensure_pipelines_fetched
	utilsLib.ensure_pipelines_exists
	count({job | job := input.Pipelines[_].jobs[_]; does_job_contain_one_of_tasks(job, pipeline_vulnerability_scan_tasks)}) == 0
	msg = {"ids": ["3.2.3"], "status": "Failed", "details": "Pipeline dependencies are not scanned for licenses"}
}
