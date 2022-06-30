package main

import data.common.consts as constsLib
import data.common.permissions as permissionslib
import data.generic.utils as utilsLib
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

CbPolicy[msg] {
	utilsLib.is_repository_data_missing
	utilsLib.is_organization_data_missing
	msg := {"ids": ["4.3.4"], "status": constsLib.status.Unknown}
}

CbPolicy[msg] {
	permissionslib.is_missing_hooks_permission
	msg := {"ids": ["4.3.4"], "status": constsLib.status.Unknown, "details": constsLib.details.hooks_missing_minimal_permissions}
}

#Looking for organization 2mfa enforcements that is disabled
CbPolicy[msg] {
	not utilsLib.is_repository_data_missing
	not utilsLib.is_organization_data_missing
	not permissionslib.is_missing_hooks_permission
	unsecuredHooks := is_org_have_unsucured_hooks[i]
	details := sprintf("%v %v", [format_int(unsecuredHooks, 10), "unsecured webhooks"])
	msg := {"ids": ["4.3.4"], "status": constsLib.status.Failed, "details": details}
}
