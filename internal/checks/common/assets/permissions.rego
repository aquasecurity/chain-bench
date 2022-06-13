package common.permissions

import future.keywords.in

#for org settings you need to have full private repo permissions(the upper checks under repo)
is_missing_org_settings_permission {
	input.Organization.DefaultRepoPermission == null
}

#for org settings you need to have full private repo permissions(the upper checks under repo)
is_missing_repo_settings_permission {
	input.Repository.AllowRebaseMerge == null
}

is_missing_org_hooks_permission {
	missingOrgPerm := to_number(input.Organization.Hooks == null)
	missingRepoPerm := to_number(input.Repository.Hooks == null)
	missingOrgPerm + missingRepoPerm > 0
}

is_missing_org_packages_permission {
	input.Registry.Packages == null
}

is_org_default_permission_strict {
	input.Organization.DefaultRepoPermission in ["read", "none"]
}