package main

import data.common.consts as constsLib
import data.common.permissions as permissionslib
import future.keywords.in

is_org_have_unsucured_hooks[unsecuredHooks] {
	hooks := array.concat(input.Organization.Hooks, input.Repository.Hooks)
	packageHooks := [p | p := hooks[_]; p.Events[t] in ["package", "registry_package"]]
	securedHooks := count({i |
		hook := packageHooks[i]
		hook.Config.Insecure_SSL == "0"
		hook.Config.Secret != null
		not regex.match("^http://", hook.Config.URL)
	})

	unsecuredHooks := count(packageHooks) - securedHooks
	unsecuredHooks > 0
}

is_two_factor_authentication_disabled_in_registry {
	input.Registry.TwoFactorRequirementEnabled == false
}

is_registry_packages_allows_anonymous_access[unauth_packages] {
	unauth_packages := count([p |
		p := input.Registry.Packages[_]
		p.Visibility == "public"
		p.Repository.IsPrivate == true
	])

	unauth_packages > 0
}

deny[msg] {
	permissionslib.is_missing_org_settings_permission
	msg := {"ids": ["4.2.3"], "status": "Unknown", "details": constsLib.details_organization_missingMinimalPermissions}
}

deny[msg] {
	permissionslib.is_missing_org_packages_permission
	msg := {"ids": ["4.2.5"], "status": "Unknown", "details": constsLib.details_organization_packages_missingMinimalPermissions}
}

deny[msg] {
	permissionslib.is_missing_org_hooks_permission
	msg := {"ids": ["4.3.4"], "status": "Unknown", "details": constsLib.details_hooks_missingMinimalPermissions}
}

deny[msg] {
	not permissionslib.is_missing_org_settings_permission
	is_two_factor_authentication_disabled_in_registry
	msg := {"ids": ["4.2.3"], "status": "Failed"}
}

deny[msg] {
	not permissionslib.is_missing_org_packages_permission
	unauth_packages := is_registry_packages_allows_anonymous_access[i]
	details := sprintf("%v %v", [format_int(unauth_packages, 10), "anonymous accessed packages"])
	msg := {"ids": ["4.2.5"], "status": "Failed", "details": details}
}

#Looking for organization 2mfa enforcements that is disabled
deny[msg] {
	not permissionslib.is_missing_org_hooks_permission
	unsecuredHooks := is_org_have_unsucured_hooks[i]
	details := sprintf("%v %v", [format_int(unsecuredHooks, 10), "unsecured webhooks"])
	msg := {"ids": ["4.3.4"], "status": "Failed", "details": details}
}
