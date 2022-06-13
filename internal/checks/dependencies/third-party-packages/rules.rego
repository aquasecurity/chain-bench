package main

import data.generic.utils as utilsLib
import future.keywords.in

is_task_version_pinned(step) {
	step.type == "task"
	step.task.version_type != "commit"
}

CbPolicy[msg] {
	not utilsLib.ensure_pipelines_fetched
	msg = {"ids": ["3.1.7"], "status": "Unknown"}
}

# In case there are no pipelines
CbPolicy[msg] {
	utilsLib.ensure_pipelines_fetched
	not utilsLib.ensure_pipelines_exists
	msg = {"ids": ["3.1.7"], "status": "Unknown", "details": "No pipelines were found"}
}

# Looking for tasks that are not pinned
CbPolicy[msg] {
	utilsLib.ensure_pipelines_fetched
	unpinnedDepsCount := count({step |
		step = input.Pipelines[_].jobs[_].steps[_]
		is_task_version_pinned(step)
	})

	unpinnedDepsCount > 0
	msg := {"ids": ["3.1.7"], "status": "Failed", "details": sprintf("%v dependenc(ies) are not pinned", [unpinnedDepsCount])}
}
