package main

import data.common.consts as constsLib
import data.common.permissions as permissionslib
import future.keywords.in

is_two_factor_authentication_disabled_in_registry {
	input.Registry.TwoFactorRequirementEnabled == false
}

is_registry_packages_allows_anonymous_access[unauth_packages] {
	unauth_packages := count([p |
		p := input.Registry.Packages[_]
		p.Repository.ID == input.Repository.ID
		p.Visibility == "public"
		p.Repository.IsPrivate == true
	])

	unauth_packages > 0
}

CbPolicy[msg] {
	permissionslib.is_missing_org_settings_permission
	msg := {"ids": ["4.2.3"], "status": constsLib.status.Unknown, "details": constsLib.details.organization_missing_minimal_permissions}
}

CbPolicy[msg] {
	permissionslib.is_missing_org_packages_permission
	msg := {"ids": ["4.2.5"], "status": constsLib.status.Unknown, "details": constsLib.details.organization_packages_missing_minimal_permissions}
}

CbPolicy[msg] {
	not permissionslib.is_missing_org_settings_permission
	is_two_factor_authentication_disabled_in_registry
	msg := {"ids": ["4.2.3"], "status": constsLib.status.Failed}
}

CbPolicy[msg] {
	not permissionslib.is_missing_org_packages_permission
	unauth_packages := is_registry_packages_allows_anonymous_access[i]
	details := sprintf("%v %v", [format_int(unauth_packages, 10), "anonymous accessed packages"])
	msg := {"ids": ["4.2.5"], "status": constsLib.status.Failed, "details": details}
}
