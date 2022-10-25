package gitlab

import (
	"testing"
	"time"

	"github.com/aquasecurity/chain-bench/internal/models"
	"github.com/aquasecurity/chain-bench/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/xanzy/go-gitlab"
)

func TestToRepository(t *testing.T) {
	repoName := "myrepo"
	time := time.Now()
	excepted := models.Repository{
		Name:          &repoName,
		ID:            utils.GetPtr(int64(433)),
		Description:   utils.GetPtr(""),
		DefaultBranch: utils.GetPtr(""),
		Owner: &models.User{
			Type: utils.GetPtr("Organization")},
		OpenIssuesCount:  utils.GetPtr(0),
		StargazersCount:  utils.GetPtr(0),
		AllowRebaseMerge: utils.GetPtr(false),
		AllowSquashMerge: utils.GetPtr(false),
		AllowMergeCommit: utils.GetPtr(false),
		IsPrivate:        utils.GetPtr(true),
		HasIssues:        utils.GetPtr(false),
		Archived:         utils.GetPtr(false),
		URL:              utils.GetPtr(""),
		CreatedAt:        &utils.Timestamp{},
		PushedAt:         &utils.Timestamp{},
		UpdatedAt:        &utils.Timestamp{},
		Branches: []*models.Branch{
			{
				Commit: &models.RepositoryCommit{
					Committer: &models.CommitAuthor{
						Date: utils.GetPtr(time),
					},
				},
			},
		},
		Commits: []*models.RepositoryCommit{
			{
				Committer: &models.CommitAuthor{
					Date: utils.GetPtr(time),
				},
			},
		},
		Hooks:                []*models.Hook{{URL: utils.GetPtr("https://example.com")}},
		Collaborators:        []*models.User{},
		IsContainsSecurityMd: true,
	}

	actual := toRepository(
		&gitlab.Project{
			Name:  repoName,
			ID:    433,
			Owner: &gitlab.User{},
		},
		[]*models.Branch{
			{
				Commit: &models.RepositoryCommit{
					Committer: &models.CommitAuthor{
						Date: utils.GetPtr(time),
					},
				},
			},
		},
		[]*models.User{},
		[]*models.Hook{{URL: utils.GetPtr("https://example.com")}},
		[]*models.RepositoryCommit{
			{
				Committer: &models.CommitAuthor{
					Date: utils.GetPtr(time),
				},
			},
		},
		true,
	)

	assert.Equal(t, excepted, *actual)
}

func TestToOrganization(t *testing.T) {
	orgName := "org1"

	excepted := models.Organization{Name: &orgName,
		IsRepositoryDeletionLimited: utils.GetPtr(false),
		IsIssueDeletionLimited:      utils.GetPtr(false),
		ID:                          utils.GetPtr(int64(33432)),
		MembersCanCreateRepos:       utils.GetPtr(false),
		Type:                        utils.GetPtr("Organization"),
		DefaultRepoPermission:       utils.GetPtr("inherit"),
		Description:                 utils.GetPtr(""),
		TwoFactorRequirementEnabled: utils.GetPtr(false),
		Hooks:                       []*models.Hook{{URL: utils.GetPtr("https://example.com")}}}

	actual := toOrganization(&gitlab.Group{ID: 33432, Name: orgName, ProjectCreationLevel: gitlab.NoOneProjectCreation}, []*models.Hook{{URL: utils.GetPtr("https://example.com")}})

	assert.Equal(t, excepted, *actual)
}
func TestToUsers(t *testing.T) {

	login := "liorvais"
	var excepted = models.User{Login: &login,
		ID:        utils.GetPtr(int64(213)),
		Type:      utils.GetPtr("User"),
		CreatedAt: &utils.Timestamp{},
		HTMLURL:   utils.GetPtr(""),
		AvatarURL: utils.GetPtr(""),
		Name:      utils.GetPtr(""),
		Location:  utils.GetPtr(""),
		Email:     utils.GetPtr(""),
		Bio:       utils.GetPtr(""),
		SiteAdmin: utils.GetPtr(false),
		URL:       utils.GetPtr("")}

	actual := toUsers([]*gitlab.User{{Username: login, ID: 213}})

	assert.Equal(t, excepted, *actual[0])
}

func TestToBranchProtection(t *testing.T) {
	excepted := models.Protection{
		AllowForcePushes: false,
		RequiredPullRequestReviews: &models.PullRequestReviewsEnforcement{
			DismissStaleReviews: true, RequiredApprovingReviewCount: 3},
		RequiredSignedCommit: true, EnforceAdmins: &models.AdminEnforcement{}}
	actual := toBranchProtection(&gitlab.Project{DefaultBranch: "main"}, &gitlab.ProtectedBranch{AllowForcePush: false}, &gitlab.ProjectApprovals{ResetApprovalsOnPush: true}, []*gitlab.ProjectApprovalRule{{ApprovalsRequired: 3}}, &gitlab.ProjectPushRules{RejectUnsignedCommits: true})

	assert.Equal(t, excepted, *actual)
}
