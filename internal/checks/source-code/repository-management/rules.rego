package main

import data.common.consts as constsLib
import data.generic.utils as utilsLib
import future.keywords.in

#checks if the repository is public one
is_public_repository {
	input.Repository.IsPrivate == false
}

# each one of public repositories should conatin security.md file
is_missing_security_md_file {
	input.Repository.IsContainsSecurityMd == false
}

is_repository_deletion_not_limited_to_trusted_memebers {
	input.Organization.IsRepositoryDeletionLimited == false
}

is_repository_creation_not_limited_to_trusted_memebers {
	input.Organization.MembersCanCreateRepos == true
}

is_issue_deletion_not_limited_to_trusted_memebers {
	input.Organization.IsIssueDeletionLimited == false
}

CbPolicy[msg] {
	utilsLib.is_repository_data_missing
	msg := {"ids": ["1.2.1"], "status": constsLib.status.Unknown, "details": constsLib.details.repository_data_is_missing}
}

CbPolicy[msg] {
	utilsLib.is_organization_data_missing
	msg := {"ids": ["1.2.2", "1.2.3", "1.2.4"], "status": constsLib.status.Unknown, "details": constsLib.details.organization_not_fetched}
}

#Looking for security md file in repository
CbPolicy[msg] {
	not utilsLib.is_repository_data_missing
	is_public_repository
	is_missing_security_md_file
	msg := {"ids": ["1.2.1"], "status": constsLib.status.Failed}
}

CbPolicy[msg] {
	not utilsLib.is_organization_data_missing
	is_repository_creation_not_limited_to_trusted_memebers
	msg := {"ids": ["1.2.2"], "status": constsLib.status.Failed}
}

CbPolicy[msg] {
	not utilsLib.is_organization_data_missing
	is_repository_deletion_not_limited_to_trusted_memebers
	msg := {"ids": ["1.2.3"], "status": constsLib.status.Failed}
}

CbPolicy[msg] {
	not utilsLib.is_organization_data_missing
	is_issue_deletion_not_limited_to_trusted_memebers
	msg := {"ids": ["1.2.4"], "status": constsLib.status.Failed}
}
