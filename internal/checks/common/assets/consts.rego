package common.consts

details := details {
	details := {
		"organization_missing_minimal_permissions": "Organization is missing minimal permissions",
		"repository_missing_minimal_permissions": "Repository is missing minimal permissions",
		"organization_packages_missing_minimal_permissions": "Organization Packages is missing minimal permissions",
		"hooks_missing_minimal_permissions": "Organization & Repository Hooks is missing minimal permissions",
		"linear_history_merge_commit_enabled": "MergeCommit is enabled for repository",
		"linear_history_require_rebase_or_squash_commit_enabled": "Repository is not configured to allow rebase or squash merge",
		"pipeline_no_pipelines_found": "No pipelines were found",
		"pipeline_no_build_job": "No build job was found in pipelines",
		"organization_premissive_default_repository_permissions": "Organization default permissions are too permissive",
		"pipeline_pipelines_not_scanned_for_vulnerabilities": "Pipelines are not scanned for vulnerabilities",
	}
}

actions := actions {
	actions := {
		"argon_scanner_action": "argonsecurity/scanner-action",
		"trivy_scanner_action": "aquasecurity/trivy-action",
	}
}

pipeline_vulnerability_scan_tasks = [actions.argon_scanner_action, actions.trivy_scanner_action]

secret_scan_tasks = [
	actions.argon_scanner_action,
	"zricethezav/gitleaks-action",
	"ShiftLeftSecurity/scan-action",
]

status := stat {
	stat := {
		"Unknown": "Unknown",
		"Failed": "Failed",
		"Success": "Success",
	}
}
