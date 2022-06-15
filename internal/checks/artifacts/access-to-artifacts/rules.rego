package main

import data.common.consts as constsLib
import data.common.permissions as permissionslib
import future.keywords.in

is_registry_enforce_two_factor_authentication {
	not permissionslib.is_missing_org_settings_permission
	input.Registry.TwoFactorRequirementEnabled == true
}

is_registry_packages_allows_anonymous_access[details] {
	not permissionslib.is_missing_org_packages_permission
	unauth_packages := count([p |
		p := input.Registry.Packages[_]
		p.Visibility == "public"
		p.Repository.IsPrivate == true
	])

	unauth_packages > 0
	details := sprintf("%v %v", [format_int(unauth_packages, 10), "anonymous accessed packages"])
}

CbPolicy[msg] {
	permissionslib.is_missing_org_settings_permission
	msg := {"ids": ["4.2.3"], "status": constsLib.status.Unknown, "details": constsLib.details_organization_missingMinimalPermissions}
}

CbPolicy[msg] {
	permissionslib.is_missing_org_packages_permission
	msg := {"ids": ["4.2.5"], "status": constsLib.status.Unknown, "details": constsLib.details_organization_packages_missingMinimalPermissions}
}

CbPolicy[msg] {
	not permissionslib.is_missing_org_settings_permission
	not is_registry_enforce_two_factor_authentication
	msg := {"ids": ["4.2.3"], "status": constsLib.status.Failed}
}

CbPolicy[msg] {
	details := is_registry_packages_allows_anonymous_access[i]
	msg := {"ids": ["4.2.5"], "status": constsLib.status.Failed, "details": details}
}
