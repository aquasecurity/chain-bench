package main

import data.common.consts as constsLib
import data.generic.utils as utilsLib
import future.keywords.in

does_job_contain_one_of_tasks(job, regexes) {
	job.steps[i].type == "task"
	regex.match(regexes[_], job.steps[i].task.name)
}

are_pipelines_dependencies_scanned_for_vulnerabilities {
	count({job | job := input.Pipelines[_].jobs[_]; does_job_contain_one_of_tasks(job, constsLib.pipeline_vulnerability_scan_tasks)}) == 0
}

are_pipelines_dependencies_scanned_for_licenses {
	count({job | job := input.Pipelines[_].jobs[_]; does_job_contain_one_of_tasks(job, constsLib.pipeline_vulnerability_scan_tasks)}) == 0
}

CbPolicy[msg] {
	utilsLib.is_pipelines_data_missing
	msg = {"ids": ["3.2.2", "3.2.3"], "status": constsLib.status.Unknown}
}

# In case there are no pipelines
CbPolicy[msg] {
	not utilsLib.is_pipelines_data_missing
	utilsLib.is_pipelines_list_empty
	msg = {"ids": ["3.2.2", "3.2.3"], "status": constsLib.status.Unknown, "details": constsLib.details.pipeline_no_pipelines_found}
}

# Looking for a pipeline that scans for vulnerabilities
CbPolicy[msg] {
	not utilsLib.is_pipelines_data_missing
	not utilsLib.is_pipelines_list_empty
	are_pipelines_dependencies_scanned_for_vulnerabilities
	msg = {"ids": ["3.2.2"], "status": constsLib.status.Failed, "details": "Pipeline dependencies are not scanned for vulnerabilities"}
}

# Looking for a pipeline that scans for licenses
CbPolicy[msg] {
	not utilsLib.is_pipelines_data_missing
	not utilsLib.is_pipelines_list_empty
	are_pipelines_dependencies_scanned_for_licenses
	msg = {"ids": ["3.2.3"], "status": constsLib.status.Failed, "details": "Pipeline dependencies are not scanned for licenses"}
}
