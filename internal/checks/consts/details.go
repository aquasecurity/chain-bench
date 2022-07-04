package consts

var (
	Details_linearHistory_mergeCommitEnabled                 = "MergeCommit is enabled for repository"
	Details_linearHistory_requireRebaseOrSquashCommitEnabled = "Repository is not configured to allow rebase or squash merge"

	Details_organization_notFetched                             = "Organization is not fetched"
	Details_organization_premissiveDefaultRepositoryPermissions = "Organization default permissions are too permissive"
	Details_organization_missingMinimalPermissions              = "Organization is missing minimal permissions"
	Details_hooks_missingMinimalPermissions                     = "Organization & Repository Hooks is missing minimal permissions"

	Details_organization_hooks_missingMinimalPermissions = "Organization Packages is missing minimal permissions"

	Details_repository_missing_minimal_permissions = "Repository is missing minimal permissions"

	Details_pipeline_pipelinesNotScannedForVulnerabilities     = "Pipelines are not scanned for vulnerabilities"
	Details_dependencies_pipelinesNotScannedForVulnerabilities = "Pipeline dependencies are not scanned for vulnerabilities"
	Details_dependencies_pipelinesNotScannedForLicenses        = "Pipeline dependencies are not scanned for licenses"
	Details_pipeline_repositoryNotScannedForSecrets            = "Repository is not scanned for secrets"
	Details_pipeline_noPipelinesFound                          = "No pipelines were found"
	Details_pipeline_noBuildJob                                = "No build job was found in pipelines"
	Details_registry_data_is_missing                           = "Registry is not fetched"
	Details_pipeline_are_missing                               = "Pipelines are not fetched"
	Details_repository_is_missing                              = "Repository is not fetched"
)
