package main

import data.common.consts as constsLib
import data.generic.utils as utilsLib
import future.keywords.in

is_task_version_pinned(step) {
	step.type == "task"
	step.task.version_type != "commit"
}

are_there_unpinned_deps[unpinnedDepsCount] {
	unpinnedDepsCount := count({step |
		step = input.Pipelines[_].jobs[_].steps[_]
		is_task_version_pinned(step)
	})

	unpinnedDepsCount > 0
}

CbPolicy[msg] {
	utilsLib.is_pipelines_data_missing
	msg = {"ids": ["3.1.7"], "status": constsLib.status.Unknown}
}

# In case there are no pipelines
CbPolicy[msg] {
	not utilsLib.is_pipelines_data_missing
	utilsLib.is_pipelines_list_empty
	msg = {"ids": ["3.1.7"], "status": constsLib.status.Unknown, "details": constsLib.details.pipeline_no_pipelines_found}
}

# Looking for tasks that are not pinned
CbPolicy[msg] {
	not utilsLib.is_pipelines_data_missing
	unpinnedDepsCount := are_there_unpinned_deps[i]
	details := sprintf("%v dependenc(ies) are not pinned", [unpinnedDepsCount])
	msg := {"ids": ["3.1.7"], "status": constsLib.status.Failed, "details": details}
}
