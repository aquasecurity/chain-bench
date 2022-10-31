package gitlab

import (
	"regexp"

	"github.com/aquasecurity/chain-bench/internal/models"
	"github.com/aquasecurity/chain-bench/internal/utils"
	"github.com/xanzy/go-gitlab"
)

func toUser(user *gitlab.User) *models.User {
	var u *models.User = nil

	if user != nil {
		u = &models.User{
			Login:     &user.Username,
			ID:        utils.GetPtr(int64(user.ID)),
			AvatarURL: &user.AvatarURL,
			HTMLURL:   &user.WebsiteURL,
			Name:      &user.Name,
			Location:  &user.Location,
			Email:     &user.Email,
			Bio:       &user.Bio,
			CreatedAt: &utils.Timestamp{Time: utils.GetValue(user.CreatedAt)},
			Type:      utils.GetPtr("User"),
			SiteAdmin: &user.IsAdmin,
			URL:       &user.WebURL,
		}
	}
	return u
}

func toUsers(users []*gitlab.User) []*models.User {
	var u []*models.User = []*models.User{}
	if users != nil {
		for _, user := range users {
			u = append(u, toUser(user))
		}
	}
	return u
}

func toRepository(repo *gitlab.Project, branches []*models.Branch, collaborators []*models.User, hooks []*models.Hook, commits []*models.RepositoryCommit, isContainsSecurityMD bool) *models.Repository {
	var r *models.Repository = nil
	if repo != nil {
		r = &models.Repository{
			ID:                   utils.GetPtr(int64(repo.ID)),
			Owner:                &models.User{Type: utils.GetPtr("Organization")},
			Name:                 &repo.Path,
			Description:          &repo.Description,
			DefaultBranch:        &repo.DefaultBranch,
			CreatedAt:            &utils.Timestamp{Time: utils.GetValue(repo.CreatedAt)},
			PushedAt:             &utils.Timestamp{Time: utils.GetValue(repo.LastActivityAt)},
			UpdatedAt:            &utils.Timestamp{Time: utils.GetValue(repo.LastActivityAt)},
			OpenIssuesCount:      &repo.OpenIssuesCount,
			StargazersCount:      &repo.StarCount,
			AllowSquashMerge:     utils.GetPtr(repo.SquashOption == gitlab.SquashOptionAlways || repo.SquashOption == gitlab.SquashOptionDefaultOn),
			AllowRebaseMerge:     utils.GetPtr(repo.MergeMethod == gitlab.RebaseMerge),
			AllowMergeCommit:     utils.GetPtr(repo.MergeMethod == gitlab.NoFastForwardMerge),
			Topics:               repo.Topics,
			License:              toLicense(repo.License),
			IsPrivate:            utils.GetPtr(!repo.Public),
			HasIssues:            utils.GetPtr(repo.OpenIssuesCount > 0),
			Archived:             &repo.Archived,
			URL:                  &repo.WebURL,
			Branches:             branches,
			Collaborators:        collaborators,
			IsContainsSecurityMd: isContainsSecurityMD,
			Commits:              commits,
			Hooks:                hooks,
		}
	}
	return r
}

func toBranches(branches []*gitlab.Branch) []*models.Branch {
	var b []*models.Branch = nil
	if branches != nil {
		for _, branch := range branches {
			b = append(b, toBranch(branch))
		}
	}
	return b
}

func toBranch(branch *gitlab.Branch) *models.Branch {
	var b *models.Branch = nil
	if branch != nil {
		b = &models.Branch{
			Name: &branch.Name,
			//TODO: Commit:    toCommit(branch.Commit),
			Protected: &branch.Protected,
		}
	}
	return b
}

func toBranchProtection(proj *gitlab.Project, protection *gitlab.ProtectedBranch, appConfig *gitlab.ProjectApprovals, appRules []*gitlab.ProjectApprovalRule, pushRules *gitlab.ProjectPushRules) *models.Protection {
	var p *models.Protection = nil
	branchRegex := regexp.MustCompile(pushRules.BranchNameRegex)
	isMatchDefault := branchRegex.Match([]byte(proj.DefaultBranch))
	approvingReviewCount := 0
	if len(appRules) > 0 {
		approvingReviewCount = appRules[0].ApprovalsRequired
	}
	if protection != nil {
		p = &models.Protection{
			EnforceAdmins: &models.AdminEnforcement{Enabled: false},
			RequiredPullRequestReviews: &models.PullRequestReviewsEnforcement{
				DismissStaleReviews:          appConfig.ResetApprovalsOnPush,
				RequireCodeOwnerReviews:      protection.CodeOwnerApprovalRequired,
				RequiredApprovingReviewCount: approvingReviewCount},
			//TODO: Restrictions: toBranchRestrictions(appConfig.Approvers, appConfig.ApproverGroups),
			AllowForcePushes:               protection.AllowForcePush,
			RequiredConversationResolution: proj.OnlyAllowMergeIfAllDiscussionsAreResolved,
			RequiredSignedCommit:           isMatchDefault && pushRules.RejectUnsignedCommits,
			//TODO: PreventSecrets:                 isMatchDefault && pushRules.PreventSecrets,
		}
	}
	return p
}

func toLicense(license *gitlab.ProjectLicense) *models.License {
	var l *models.License = nil
	if license != nil {
		l = &models.License{
			Key:         &license.Key,
			Name:        &license.Nickname,
			Description: &license.Name,
			URL:         &license.SourceURL,
		}
	}
	return l
}

func toOrganization(group *gitlab.Group, hooks []*models.Hook) *models.Organization {
	var o *models.Organization = nil

	if group != nil {
		o = &models.Organization{
			ID:                          utils.GetPtr(int64(group.ID)),
			Name:                        &group.Name,
			Description:                 &group.Description,
			CreatedAt:                   group.CreatedAt,
			Type:                        utils.GetPtr("Organization"),
			DefaultRepoPermission:       utils.GetPtr("inherit"),
			MembersCanCreateRepos:       utils.GetPtr(group.ProjectCreationLevel != gitlab.NoOneProjectCreation),
			TwoFactorRequirementEnabled: &group.RequireTwoFactorAuth,
			// always enforced on gitlab
			IsRepositoryDeletionLimited: utils.GetPtr(false),
			// always enforced on gitlab
			IsIssueDeletionLimited: utils.GetPtr(false),
			Hooks:                  hooks,
		}
	}
	return o
}
