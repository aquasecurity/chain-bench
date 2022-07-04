package common.consts

details := details {
	details := {
		"organization_missing_minimal_permissions": "Organization is missing minimal permissions",
		"organization_not_fetched": "Organization is not fetched",
		"organization_packages_missing_minimal_permissions": "Organization Packages is missing minimal permissions",
		"organization_premissive_default_repository_permissions": "Organization default permissions are too permissive",
		"repository_missing_minimal_permissions": "Repository is missing minimal permissions",
		"repository_data_is_missing": "Repository is not fetched",
		"hooks_missing_minimal_permissions": "Organization & Repository Hooks is missing minimal permissions",
		"linear_history_merge_commit_enabled": "MergeCommit is enabled for repository",
		"linear_history_require_rebase_or_squash_commit_enabled": "Repository is not configured to allow rebase or squash merge",
		"pipeline_no_pipelines_found": "No pipelines were found",
		"pipeline_no_build_job": "No build job was found in pipelines",
		"pipeline_data_is_missing": "Pipelines are not fetched",
		"pipeline_pipelines_not_scanned_for_vulnerabilities": "Pipelines are not scanned for vulnerabilities",
		"pipeline_repository_not_scanned_for_secrets": "Repository is not scanned for secrets",
		"dependencies_pipelines_not_scanned_for_vulnerabilities": "Pipeline dependencies are not scanned for vulnerabilities",
		"dependencies_pipelines_not_scanned_for_licenses": "Pipeline dependencies are not scanned for licenses",
		"registry_data_is_missing": "Registry is not fetched",
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
