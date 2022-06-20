package common.consts

details_organization_missingMinimalPermissions := msg {
	msg := "Organization is missing minimal permissions"
}

details_repository_missingMinimalPermissions := msg {
	msg := "Repository is missing minimal permissions"
}

details_organization_packages_missingMinimalPermissions := msg {
	msg := "Organization Packages is missing minimal permissions"
}

details_hooks_missingMinimalPermissions := msg {
	msg := "Organization & Repository Hooks is missing minimal permissions"
}

details_linearHistory_mergeCommitEnabled := msg {
	msg := "MergeCommit is enabled for repository"
}

details_linearHistory_requireRebaseOrSquashCommitEnabled := msg {
	msg := "Repository is not configured to allow rebase or squash merge"
}

details_pipeline_noPipelinesFound := msg {
	msg := "No pipelines were found"
}

details_pipeline_noBuildJob := msg {
	msg := "No build job was found in pipelines"
}

details_organization_premissiveDefaultRepositoryPermissions := msg {
	msg := "Organization default permissions are too permissive"
}

details_pipeline_pipelinesNotScannedForVulnerabilities := msg {
	msg := "Pipelines are not scanned for vulnerabilities"
}

argon_scanner_action := "argonsecurity/scanner-action"

trivy_scanner_action := "aquasecurity/trivy-action"

status := stat {
	stat := {
		"Unknown": "Unknown",
		"Failed": "Failed",
		"Success": "Success",
	}
}
