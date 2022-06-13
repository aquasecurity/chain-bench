package github

import (
	"github.com/aquasecurity/chain-bench/internal/logger"
	"github.com/aquasecurity/chain-bench/internal/models"
	"github.com/aquasecurity/chain-bench/internal/utils"
	pipelineConsts "github.com/argonsecurity/pipeline-parser/pkg/consts"
	pipelineHandler "github.com/argonsecurity/pipeline-parser/pkg/handler"
	pipelineModels "github.com/argonsecurity/pipeline-parser/pkg/models"
	"github.com/google/go-github/v41/github"
	"github.com/mitchellh/mapstructure"
)

func toRepository(repo *github.Repository, branches []*models.Branch, collaborators []*models.User, hooks []*models.Hook, commits []*models.RepositoryCommit, isContainsSecurityMD bool) *models.Repository {
	var r *models.Repository = nil
	if repo != nil {
		r = &models.Repository{
			ID:                   repo.ID,
			NodeID:               repo.NodeID,
			Owner:                toUser(repo.Owner),
			Name:                 repo.Name,
			Description:          repo.Description,
			DefaultBranch:        repo.DefaultBranch,
			MasterBranch:         repo.MasterBranch,
			CreatedAt:            (*utils.Timestamp)(repo.CreatedAt),
			PushedAt:             (*utils.Timestamp)(repo.PushedAt),
			UpdatedAt:            (*utils.Timestamp)(repo.UpdatedAt),
			Language:             repo.Language,
			Fork:                 repo.Fork,
			ForksCount:           repo.ForksCount,
			NetworkCount:         repo.NetworkCount,
			OpenIssuesCount:      repo.OpenIssuesCount,
			StargazersCount:      repo.StargazersCount,
			SubscribersCount:     repo.SubscribersCount,
			Size:                 repo.Size,
			AutoInit:             repo.AutoInit,
			AllowRebaseMerge:     repo.AllowRebaseMerge,
			AllowSquashMerge:     repo.AllowSquashMerge,
			AllowMergeCommit:     repo.AllowMergeCommit,
			Topics:               repo.Topics,
			License:              toLicense(repo.License),
			IsPrivate:            repo.Private,
			HasIssues:            repo.HasIssues,
			LicenseTemplate:      repo.LicenseTemplate,
			GitignoreTemplate:    repo.GitignoreTemplate,
			Archived:             repo.Archived,
			TeamID:               repo.TeamID,
			URL:                  repo.URL,
			Branches:             branches,
			Collaborators:        collaborators,
			IsContainsSecurityMd: isContainsSecurityMD,
			Commits:              commits,
			Hooks:                hooks,
		}
	}
	return r
}

func toLicense(license *github.License) *models.License {
	var l *models.License = nil
	if license != nil {
		l = &models.License{
			Key:            license.Name,
			Name:           license.Name,
			URL:            license.URL,
			SPDXID:         license.SPDXID,
			HTMLURL:        license.HTMLURL,
			Featured:       license.Featured,
			Description:    license.Description,
			Implementation: license.Implementation,
			Permissions:    license.Permissions,
			Conditions:     license.Conditions,
			Limitations:    license.Limitations,
			Body:           license.Body,
		}
	}
	return l
}

func toPlan(plan *github.Plan) *models.Plan {
	var p *models.Plan = nil
	if plan != nil {
		p = &models.Plan{
			Name:          plan.Name,
			Space:         plan.Space,
			Collaborators: plan.Collaborators,
			PrivateRepos:  plan.PrivateRepos,
		}
	}
	return p
}

func toOrganization(org *github.Organization, hooks []*models.Hook) *models.Organization {
	var o *models.Organization = nil

	if org != nil {
		o = &models.Organization{
			Login:                         org.Login,
			ID:                            org.ID,
			NodeID:                        org.NodeID,
			Name:                          org.Name,
			Description:                   org.Description,
			PublicRepos:                   org.PublicRepos,
			CreatedAt:                     org.CreatedAt,
			UpdatedAt:                     org.UpdatedAt,
			TotalPrivateRepos:             org.TotalPrivateRepos,
			OwnedPrivateRepos:             org.OwnedPrivateRepos,
			Collaborators:                 org.Collaborators,
			Type:                          org.Type,
			Plan:                          toPlan(org.Plan),
			DefaultRepoPermission:         org.DefaultRepoPermission,
			DefaultRepoSettings:           org.DefaultRepoSettings,
			MembersCanCreateRepos:         org.MembersCanCreateRepos,
			MembersCanCreatePublicRepos:   org.MembersCanCreatePublicRepos,
			MembersCanCreatePrivateRepos:  org.MembersCanCreatePrivateRepos,
			MembersCanCreateInternalRepos: org.MembersCanCreateInternalRepos,
			TwoFactorRequirementEnabled:   org.TwoFactorRequirementEnabled,
			IsVerified:                    org.IsVerified,
			// always enforced on github
			IsRepositoryDeletionLimited: utils.GetPtr(true),
			// always enforced on github
			IsIssueDeletionLimited: utils.GetPtr(true),
			Hooks:                  hooks,
		}
	}
	return o
}

func toBranchProtection(protection *github.Protection, signatures *github.SignaturesProtectedBranch) *models.Protection {
	var p *models.Protection = nil
	if protection != nil {
		p = &models.Protection{
			RequiredStatusChecks:           toRequiredStatusChecks(protection.RequiredStatusChecks),
			RequiredPullRequestReviews:     toPullRequestReviewsEnforcement(protection.RequiredPullRequestReviews),
			EnforceAdmins:                  &models.AdminEnforcement{Enabled: utils.GetValue(protection.EnforceAdmins).Enabled},
			Restrictions:                   toBranchRestrictions(protection.Restrictions),
			RequireLinearHistory:           utils.GetValue(protection.RequireLinearHistory).Enabled,
			AllowForcePushes:               utils.GetValue(protection.AllowForcePushes).Enabled,
			AllowDeletions:                 utils.GetValue(protection.AllowDeletions).Enabled,
			RequiredConversationResolution: utils.GetValue(protection.RequiredConversationResolution).Enabled,
			RequiredSignedCommit:           utils.GetValue(signatures.Enabled),
		}
	}
	return p
}

func toBranches(branches []*github.Branch) []*models.Branch {
	var b []*models.Branch = nil
	if branches != nil {
		for _, branch := range branches {
			b = append(b, toBranch(branch))
		}

	}
	return b
}

func toBranch(branch *github.Branch) *models.Branch {
	var b *models.Branch = nil
	if branch != nil {
		b = &models.Branch{
			Name:      branch.Name,
			Commit:    toCommit(branch.Commit),
			Protected: branch.Protected,
		}
	}
	return b
}

func toRegistry(packages []*github.Package, twoFactorRequirementEnabled *bool) *models.PackageRegistry {
	var r *models.PackageRegistry = &models.PackageRegistry{TwoFactorRequirementEnabled: twoFactorRequirementEnabled}
	if packages != nil {
		r.Packages = toPackages(packages)
	}
	return r
}

func toPackages(packages []*github.Package) []*models.Package {
	var p []*models.Package = nil
	if packages != nil {
		p = []*models.Package{}
		for _, package_ := range packages {
			p = append(p, toPackage(package_))
		}
	}
	return p
}

func toPackage(package_ *github.Package) *models.Package {
	var p *models.Package = nil
	if package_ != nil {
		p = &models.Package{
			ID:           package_.ID,
			Name:         package_.Name,
			PackageType:  package_.PackageType,
			HTMLURL:      package_.HTMLURL,
			CreatedAt:    (*utils.Timestamp)(package_.CreatedAt),
			UpdatedAt:    (*utils.Timestamp)(package_.UpdatedAt),
			Owner:        toUser(package_.Owner),
			Version:      utils.GetValue(package_.PackageVersion).Version,
			URL:          package_.URL,
			VersionCount: package_.VersionCount,
			Visibility:   package_.Visibility,
			Repository:   toRepository(package_.Repository, nil, nil, nil, nil, false),
		}
	}
	return p
}

func toBranchRestrictions(restrictions *github.BranchRestrictions) *models.BranchRestrictions {
	var r *models.BranchRestrictions = nil
	if restrictions != nil {
		r = &models.BranchRestrictions{
			Users: toUsers(restrictions.Users),
			Teams: toTeams(restrictions.Teams),
			Apps:  toApps(restrictions.Apps),
		}
	}
	return r
}

func toCommit(commit *github.RepositoryCommit) *models.RepositoryCommit {
	var c *models.RepositoryCommit = nil
	if commit != nil {
		c = &models.RepositoryCommit{
			NodeID:       commit.NodeID,
			SHA:          commit.SHA,
			Author:       toAuthor(commit),
			Committer:    toCommitAuthor(commit.GetCommit().Committer),
			URL:          commit.URL,
			Verification: nil,
		}
	}
	return c
}

func toCommits(commits []*github.RepositoryCommit) []*models.RepositoryCommit {
	results := make([]*models.RepositoryCommit, 0)
	for _, c := range commits {
		results = append(results, toCommit(c))
	}
	return results
}

func toAuthor(rc *github.RepositoryCommit) *models.CommitAuthor {
	var c *models.CommitAuthor = nil
	if rc != nil {
		commit := rc.GetCommit()
		if commit != nil {
			c = toCommitAuthor(commit.GetAuthor())
			c.Login = utils.GetValue(rc.GetAuthor()).Login
		}
	}
	return c
}

func toCommitAuthor(author *github.CommitAuthor) *models.CommitAuthor {
	var a *models.CommitAuthor = nil
	if author != nil {
		a = &models.CommitAuthor{
			Date:  author.Date,
			Name:  author.Name,
			Email: author.Email,
			Login: author.Login,
		}
	}
	return a
}

func toUser(user *github.User) *models.User {
	var u *models.User = nil
	if user != nil {
		u = &models.User{
			Login:             user.Login,
			ID:                user.ID,
			NodeID:            user.NodeID,
			AvatarURL:         user.AvatarURL,
			HTMLURL:           user.HTMLURL,
			GravatarID:        user.GravatarID,
			Name:              user.Name,
			Company:           user.Company,
			Blog:              user.Blog,
			Location:          user.Location,
			Email:             user.Email,
			Hireable:          user.Hireable,
			Bio:               user.Bio,
			PublicRepos:       user.PublicRepos,
			PublicGists:       user.PublicGists,
			Followers:         user.Followers,
			Following:         user.Following,
			CreatedAt:         (*utils.Timestamp)(user.CreatedAt),
			UpdatedAt:         (*utils.Timestamp)(user.UpdatedAt),
			SuspendedAt:       (*utils.Timestamp)(user.SuspendedAt),
			Type:              user.Type,
			SiteAdmin:         user.SiteAdmin,
			TotalPrivateRepos: user.TotalPrivateRepos,
			OwnedPrivateRepos: user.OwnedPrivateRepos,
			PrivateGists:      user.PrivateGists,
			DiskUsage:         user.DiskUsage,
			Collaborators:     user.Collaborators,
			Plan:              toPlan(user.Plan),
			URL:               user.URL,
			EventsURL:         user.EventsURL,
			FollowingURL:      user.FollowersURL,
			FollowersURL:      user.FollowersURL,
			GistsURL:          user.GistsURL,
			OrganizationsURL:  user.OrganizationsURL,
			ReceivedEventsURL: user.ReceivedEventsURL,
			ReposURL:          user.ReposURL,
			StarredURL:        user.StarredURL,
			SubscriptionsURL:  user.SubscriptionsURL,
			Permissions:       &user.Permissions,
		}
	}
	return u
}

func toUsers(users []*github.User) []*models.User {
	var u []*models.User = []*models.User{}
	if users != nil {
		for _, user := range users {
			u = append(u, toUser(user))
		}
	}
	return u
}

func toTeams(teams []*github.Team) []*models.Team {
	var t []*models.Team = []*models.Team{}
	if teams != nil {
		for _, team := range teams {
			t = append(t, toTeam(team))
		}
	}
	return t
}

func toTeam(team *github.Team) *models.Team {
	var t *models.Team = nil
	if team != nil {
		t = &models.Team{
			ID:           team.ID,
			Name:         team.Name,
			Description:  team.Description,
			URL:          team.URL,
			Slug:         team.Slug,
			Permission:   team.Permission,
			Permissions:  team.Permissions,
			Privacy:      team.Privacy,
			MembersCount: team.MembersCount,
			ReposCount:   team.ReposCount,
		}
	}
	return t
}

func toApps(apps []*github.App) []*models.App {
	var a []*models.App = []*models.App{}
	if apps != nil {
		for _, app := range apps {
			a = append(a, toApp(app))
		}
	}
	return a
}

func toApp(app *github.App) *models.App {
	var a *models.App = nil
	if app != nil {
		a = &models.App{
			ID:          app.ID,
			Slug:        app.Slug,
			NodeID:      app.NodeID,
			Owner:       toUser(app.Owner),
			Name:        app.Name,
			Description: app.Description,
			ExternalURL: app.ExternalURL,
			HTMLURL:     app.HTMLURL,
			CreatedAt:   (*utils.Timestamp)(app.CreatedAt),
			UpdatedAt:   (*utils.Timestamp)(app.UpdatedAt),
			Permissions: toInstallationPermission(app.Permissions),
			Events:      app.Events,
		}
	}
	return a
}
func toInstallationPermission(permissions *github.InstallationPermissions) *models.InstallationPermissions {
	var p *models.InstallationPermissions = nil
	if permissions != nil {
		p = &models.InstallationPermissions{
			Actions:                       permissions.Actions,
			Administration:                permissions.Administration,
			Blocking:                      permissions.Blocking,
			Checks:                        permissions.Checks,
			Contents:                      permissions.Contents,
			ContentReferences:             permissions.ContentReferences,
			Deployments:                   permissions.Deployments,
			Emails:                        permissions.Emails,
			Environments:                  permissions.Environments,
			Followers:                     permissions.Followers,
			Issues:                        permissions.Issues,
			Metadata:                      permissions.Metadata,
			Members:                       permissions.Members,
			OrganizationAdministration:    permissions.OrganizationAdministration,
			OrganizationHooks:             permissions.OrganizationAdministration,
			OrganizationPlan:              permissions.OrganizationPlan,
			OrganizationPreReceiveHooks:   permissions.OrganizationPreReceiveHooks,
			OrganizationProjects:          permissions.OrganizationProjects,
			OrganizationSecrets:           permissions.OrganizationSecrets,
			OrganizationSelfHostedRunners: permissions.OrganizationSelfHostedRunners,
			OrganizationUserBlocking:      permissions.OrganizationUserBlocking,
			Packages:                      permissions.Packages,
			Pages:                         permissions.Pages,
			PullRequests:                  permissions.PullRequests,
			RepositoryHooks:               permissions.RepositoryHooks,
			RepositoryProjects:            permissions.RepositoryProjects,
			RepositoryPreReceiveHooks:     permissions.RepositoryPreReceiveHooks,
			Secrets:                       permissions.Secrets,
			SecretScanningAlerts:          permissions.SecretScanningAlerts,
			SecurityEvents:                permissions.SecurityEvents,
			SingleFile:                    permissions.SingleFile,
			Statuses:                      permissions.Statuses,
			TeamDiscussions:               permissions.TeamDiscussions,
			VulnerabilityAlerts:           permissions.VulnerabilityAlerts,
			Workflows:                     permissions.Workflows,
		}
	}
	return p
}

func toPullRequestReviewsEnforcement(review *github.PullRequestReviewsEnforcement) *models.PullRequestReviewsEnforcement {
	var r *models.PullRequestReviewsEnforcement = nil
	if review != nil {
		r = &models.PullRequestReviewsEnforcement{
			DismissalRestrictions:        toDismissalRestrictions(review.DismissalRestrictions),
			DismissStaleReviews:          review.DismissStaleReviews,
			RequireCodeOwnerReviews:      review.RequireCodeOwnerReviews,
			RequiredApprovingReviewCount: review.RequiredApprovingReviewCount,
		}
	}
	return r
}

func toRequiredStatusChecks(statusChecks *github.RequiredStatusChecks) *models.RequiredStatusChecks {
	var r *models.RequiredStatusChecks = nil
	if statusChecks != nil {
		r = &models.RequiredStatusChecks{Strict: statusChecks.Strict}
	}

	return r
}

func toDismissalRestrictions(dismissal *github.DismissalRestrictions) *models.DismissalRestrictions {
	var d *models.DismissalRestrictions = nil
	if dismissal != nil {
		d = &models.DismissalRestrictions{
			Users: toUsers(dismissal.Users),
		}
	}
	return d
}

func toPipeline(buf []byte) (*pipelineModels.Pipeline, error) {
	return pipelineHandler.Handle(buf, pipelineConsts.GitHubPlatform)
}

func toHooks(hooks []*github.Hook) []*models.Hook {
	var h []*models.Hook = nil
	if hooks != nil {
		for _, hook := range hooks {
			h = append(h, toHook(hook))
		}
	}
	return h
}

func toHook(hook *github.Hook) *models.Hook {
	var h *models.Hook = nil
	if hook != nil {
		h = &models.Hook{
			CreatedAt:    hook.CreatedAt,
			UpdatedAt:    hook.UpdatedAt,
			URL:          hook.URL,
			ID:           hook.ID,
			Type:         hook.Type,
			Name:         hook.Name,
			TestURL:      hook.TestURL,
			PingURL:      hook.PingURL,
			LastResponse: hook.LastResponse,
			Events:       hook.Events,
			Active:       hook.Active,
			Config:       toHookConfig(hook.Config),
		}
	}
	return h
}

func toHookConfig(config map[string]interface{}) *models.HookConfig {
	var c *models.HookConfig = nil
	if err := mapstructure.Decode(config, &c); err != nil {
		logger.Error(err, "error in parsing hook config")
	}
	return c
}
