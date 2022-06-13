package main

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

#Looking for security md file in repository
CbPolicy[msg] {
	is_public_repository
	is_missing_security_md_file
	msg := {"ids": ["1.2.1"], "status": "Failed"}
}

CbPolicy[msg] {
	is_repository_creation_not_limited_to_trusted_memebers
	msg := {"ids": ["1.2.2"], "status": "Failed"}
}

CbPolicy[msg] {
	is_repository_deletion_not_limited_to_trusted_memebers
	msg := {"ids": ["1.2.3"], "status": "Failed"}
}

CbPolicy[msg] {
	is_issue_deletion_not_limited_to_trusted_memebers
	msg := {"ids": ["1.2.4"], "status": "Failed"}
}
