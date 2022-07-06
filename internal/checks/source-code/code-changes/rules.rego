package main

import data.common.consts as constsLib
import data.common.permissions as permissionslib
import data.generic.utils as utilsLib
import future.keywords.in

# for repository without branch protection setting
is_no_branch_protection {
	permissionslib.is_repo_admin
	input.BranchProtections == null
}

is_branch_protection_not_requires_status_check {
	not is_no_branch_protection
	input.BranchProtections.RequiredStatusChecks == null
}

is_branch_protection_not_requires_two_minimum_reviewers_before_merge {
	input.BranchProtections.RequiredPullRequestReviews.RequiredApprovingReviewCount < 2
}

is_branch_protection_not_requires_code_owner_review {
	input.BranchProtections.RequiredPullRequestReviews.RequireCodeOwnerReviews == false
}

is_branch_protection_not_requires_dismiss_stale_reviews {
	input.BranchProtections.RequiredPullRequestReviews.DismissStaleReviews == false
}

is_branch_protection_not_requires_dismissal_restrictions {
	input.BranchProtections.RequiredPullRequestReviews.DismissalRestrictions == null
}

is_required_pull_request_reviews_disabled {
	input.BranchProtections.RequiredPullRequestReviews == null
}

is_branch_protection_not_requires_conversation_resolution {
	input.BranchProtections.RequiredConversationResolution == false
}

is_branch_protection_not_requires_signed_commits {
	input.BranchProtections.RequiredSignedCommit == false
}

is_branch_protection_not_enforced_on_admins {
	input.BranchProtections.EnforceAdmins.Enabled == false
}

is_branch_protection_restrict_force_push {
	input.BranchProtections.AllowForcePushes == false
}

is_branch_protection_restrict_delete_branch {
	input.BranchProtections.AllowDeletions == false
}

is_branch_protection_not_restrict_who_can_push {
	input.BranchProtections.Restrictions == null
}

is_branch_protection_not_restrict_who_can_push {
	input.BranchProtections.Restrictions != null
	restrictUsers := count(input.BranchProtections.Restrictions.Users)
	restrictTeams := count(input.BranchProtections.Restrictions.Teams)
	restrictApps := count(input.BranchProtections.Restrictions.Apps)

	(restrictUsers + restrictTeams) + restrictApps == 0
}

is_branch_protection_not_requires_branch_up_to_date_before_merge {
	input.BranchProtections.RequiredStatusChecks.Strict == false
}

#looking for branches that the last commit pushed more than 2 month ago
is_inactive_branches[inactiveCount] {
	input.Repository.Branches != null
	threshold := time.add_date(time.now_ns(), 0, -2, 0)

	inactiveCount := count({i |
		branch := input.Repository.Branches[i]
		time.parse_rfc3339_ns(branch.Commit.Committer.Date) < threshold
	})

	inactiveCount > 0
}

is_repository_allow_merge_commit {
	input.Repository.AllowMergeCommit == true
}

is_repository_prevent_rebase_and_squash_merge {
	input.Repository.AllowRebaseMerge == false
	input.Repository.AllowSquashMerge == false
}

#couldnt get repository data
CbPolicy[msg] {
	utilsLib.is_repository_data_missing
	msg := {"ids": ["1.1.3", "1.1.4", "1.1.5", "1.1.6", "1.1.8", "1.1.9", "1.1.10", "1.1.11", "1.1.12", "1.1.13", "1.1.14", "1.1.15", "1.1.16", "1.1.17"], "status": constsLib.status.Unknown, "details": constsLib.details.repository_data_is_missing}
}

#missing permissions
CbPolicy[msg] {
	not utilsLib.is_repository_data_missing
	permissionslib.is_missing_repo_settings_permission
	msg := {"ids": ["1.1.3", "1.1.4", "1.1.5", "1.1.6", "1.1.9", "1.1.10", "1.1.11", "1.1.12", "1.1.13", "1.1.14", "1.1.15", "1.1.16", "1.1.17"], "status": constsLib.status.Unknown, "details": constsLib.details.repository_missing_minimal_permissions}
}

#Missing minimal permission for branch protection settings
CbPolicy[msg] {
	input.Repository.Collaborators != null
	not permissionslib.is_repo_admin
	msg := {"ids": ["1.1.3", "1.1.4", "1.1.5", "1.1.6", "1.1.9", "1.1.10", "1.1.11", "1.1.12", "1.1.14", "1.1.15", "1.1.16", "1.1.17"], "status": constsLib.status.Unknown, "details": constsLib.details.repository_missing_minimal_permissions_for_branch_protection}
}

#Missing branch protection settings
CbPolicy[msg] {
	not utilsLib.is_repository_data_missing
	not permissionslib.is_missing_repo_settings_permission
	is_no_branch_protection
	msg := {"ids": ["1.1.3", "1.1.4", "1.1.5", "1.1.6", "1.1.9", "1.1.10", "1.1.11", "1.1.12", "1.1.14", "1.1.15", "1.1.16", "1.1.17"], "status": constsLib.status.Failed}
}

CbPolicy[msg] {
	input.Repository.Collaborators == null
	msg := {"ids": ["1.1.5"], "status": constsLib.status.Unknown}
}

CbPolicy[msg] {
	is_required_pull_request_reviews_disabled
	msg := {"ids": ["1.1.3", "1.1.4", "1.1.5", "1.1.6"], "status": constsLib.status.Failed}
}

CbPolicy[msg] {
	not is_no_branch_protection
	is_branch_protection_not_requires_two_minimum_reviewers_before_merge
	msg := {"ids": ["1.1.3"], "status": constsLib.status.Failed}
}

#Looking for default branch protection that doesn't requires dismiss stale reviews
CbPolicy[msg] {
	not is_no_branch_protection
	is_branch_protection_not_requires_dismiss_stale_reviews
	msg := {"ids": ["1.1.4"], "status": constsLib.status.Failed}
}

#Looking for default branch protection that doesn't require dismissal rules
CbPolicy[msg] {
	not is_no_branch_protection
	is_branch_protection_not_requires_dismissal_restrictions
	msg := {"ids": ["1.1.5"], "status": constsLib.status.Failed}
}

CbPolicy[msg] {
	not is_no_branch_protection
	is_branch_protection_not_requires_code_owner_review
	msg := {"ids": ["1.1.6"], "status": constsLib.status.Failed}
}

#Looking for inactive branches
CbPolicy[msg] {
	not utilsLib.is_repository_data_missing
	inactiveCount := is_inactive_branches[i]
	details := sprintf("%v %v", [format_int(inactiveCount, 10), "inactive branches"])
	msg := {"ids": ["1.1.8"], "status": constsLib.status.Failed, "details": details}
}

#Looking for default branch protection that doesn't requires status check
CbPolicy[msg] {
	not is_no_branch_protection
	is_branch_protection_not_requires_status_check
	msg := {"ids": ["1.1.9", "1.1.10"], "status": constsLib.status.Failed}
}

#Looking for default branch protection that doesn't enforce branch to be up to date before merge
CbPolicy[msg] {
	not is_no_branch_protection
	not is_branch_protection_not_requires_status_check
	is_branch_protection_not_requires_branch_up_to_date_before_merge
	msg := {"ids": ["1.1.10"], "status": constsLib.status.Failed}
}

#Looking for default branch protection that doesn't requires conversation resolution before merging
CbPolicy[msg] {
	not is_no_branch_protection
	is_branch_protection_not_requires_conversation_resolution
	msg := {"ids": ["1.1.11"], "status": constsLib.status.Failed}
}

#Looking for default branch protection that doesn't requires signed commmits
CbPolicy[msg] {
	not is_no_branch_protection
	is_branch_protection_not_requires_signed_commits
	msg := {"ids": ["1.1.12"], "status": constsLib.status.Failed}
}

CbPolicy[msg] {
	is_repository_allow_merge_commit
	msg := {"ids": ["1.1.13"], "status": constsLib.status.Failed, "details": constsLib.details.linear_history_merge_commit_enabled}
}

CbPolicy[msg] {
	is_repository_prevent_rebase_and_squash_merge
	msg := {"ids": ["1.1.13"], "status": constsLib.status.Failed, "details": constsLib.details.linear_history_require_rebase_or_squash_commit_enabled}
}

#Looking for default branch protection that doesn't enforced on admins
CbPolicy[msg] {
	not is_no_branch_protection
	is_branch_protection_not_enforced_on_admins
	msg := {"ids": ["1.1.14"], "status": constsLib.status.Failed}
}

#Looking for default branch protection that restrict who can push to protected branch
CbPolicy[msg] {
	not is_no_branch_protection
	is_branch_protection_not_restrict_who_can_push
	msg := {"ids": ["1.1.15"], "status": constsLib.status.Failed}
}

#Looking for default branch protection that restrict force push to branch
CbPolicy[msg] {
	not is_no_branch_protection
	is_branch_protection_restrict_force_push
	msg := {"ids": ["1.1.16"], "status": constsLib.status.Failed}
}

#Looking for default branch protection that restrict who can delete protected branch
CbPolicy[msg] {
	not is_no_branch_protection
	is_branch_protection_restrict_delete_branch
	msg := {"ids": ["1.1.17"], "status": constsLib.status.Failed}
}
