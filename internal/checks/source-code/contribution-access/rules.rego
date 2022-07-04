package main

import data.common.consts as constsLib
import data.common.permissions as permissionslib
import data.generic.utils as utilsLib
import future.keywords.in

# for repository without branch protection setting
is_no_branch_protection {
	input.BranchProtections == null
}

is_2mfa_enforcement_disabled {
	input.Organization.TwoFactorRequirementEnabled == false
}

is_not_verified {
	input.Organization.IsVerified == false
}

is_less_then_two_admins {
	input.Organization.Members != null
	adminCount := count({i |
		input.Organization.Members[i].Role == "admin"
	})

	adminCount < 2
}

is_repository_dont_have_2_admins {
	filtered := [c | c := input.Repository.Collaborators[_]; c.permissions.admin == true]
	count(filtered) != 2
}

is_repo_has_no_commits {
	not input.Repository.Commits
}

is_repo_has_no_commits {
	input.Repository.Commits == null
}

is_organization_admin {
	input.Organization.Members != null
	count(input.Organization.Members) != 0
}

is_repository_has_inactive_users[inactiveCount] {
	filtered := [m |
		m := input.Organization.Members[_]
		count({i | input.Repository.Commits[i].Author.username == m.login}) == 0
	]

	inactiveCount := count(filtered)
	inactiveCount > 0
}

CbPolicy[msg] {
	utilsLib.is_repository_data_missing
	msg := {"ids": ["1.3.1", "1.3.7"], "status": constsLib.status.Unknown, "details": constsLib.details.repository_data_is_missing}
}

#Looking for organization missing data
CbPolicy[msg] {
	utilsLib.is_organization_data_missing
	msg := {"ids": ["1.3.3", "1.3.5", "1.3.7", "1.3.8", "1.3.9"], "status": constsLib.status.Unknown, "details": constsLib.details.organization_not_fetched}
}

#Looking for organization missing permissions
CbPolicy[msg] {
	not utilsLib.is_organization_data_missing
	permissionslib.is_missing_org_settings_permission
	msg := {"ids": ["1.3.3", "1.3.5", "1.3.7", "1.3.8"], "status": constsLib.status.Unknown}
}

CbPolicy[msg] {
	not utilsLib.is_organization_data_missing
	not permissionslib.is_missing_org_settings_permission
	not is_organization_admin
	msg := {"ids": ["1.3.3"], "status": constsLib.status.Unknown}
}

CbPolicy[msg] {
	not utilsLib.is_repository_data_missing
	is_repo_has_no_commits
	msg := {"ids": ["1.3.1"], "status": constsLib.status.Unknown}
}

# Check if organization inactive users
CbPolicy[msg] {
	not is_repo_has_no_commits
	inactiveCount := is_repository_has_inactive_users[i]
	details := sprintf("%v %v", [format_int(inactiveCount, 10), "inactive users"])
	msg := {"ids": ["1.3.1"], "status": constsLib.status.Failed, "details": details}
}

# Check if organization has min 2 admins
CbPolicy[msg] {
	is_less_then_two_admins
	msg := {"ids": ["1.3.3"], "status": constsLib.status.Failed}
}

#Looking for organization 2mfa enforcements that is disabled
CbPolicy[msg] {
	not utilsLib.is_organization_data_missing
	not permissionslib.is_missing_org_settings_permission
	is_2mfa_enforcement_disabled
	msg := {"ids": ["1.3.5"], "status": constsLib.status.Failed}
}

#Looking for repository with no 2 admins
CbPolicy[msg] {
	not utilsLib.is_repository_data_missing
	not permissionslib.is_missing_org_settings_permission
	is_repository_dont_have_2_admins
	msg := {"ids": ["1.3.7"], "status": constsLib.status.Failed}
}

#Looking for organization with non strict base permission
CbPolicy[msg] {
	not utilsLib.is_organization_data_missing
	not permissionslib.is_missing_org_settings_permission
	not permissionslib.is_org_default_permission_strict
	msg := {"ids": ["1.3.8"], "status": constsLib.status.Failed}
}

#Looking for organization that is not verified
CbPolicy[msg] {
	is_not_verified
	msg := {"ids": ["1.3.9"], "status": constsLib.status.Failed}
}
