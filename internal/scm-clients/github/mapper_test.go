package github

import (
	"testing"
	"time"

	"github.com/argonsecurity/chain-bench/internal/models"
	"github.com/argonsecurity/chain-bench/internal/utils"
	pipelineParserModels "github.com/argonsecurity/pipeline-parser/pkg/models"
	"github.com/google/go-github/v41/github"
	"github.com/stretchr/testify/assert"
)

func TestToRepository(t *testing.T) {
	repoName := "myrepo"
	time := time.Now()
	excepted := models.Repository{Name: &repoName,
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
		&github.Repository{Name: &repoName},
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

	excepted := models.Organization{Name: &orgName, MembersCanCreatePrivateRepos: utils.GetPtr(true), IsRepositoryDeletionLimited: utils.GetPtr(true), IsIssueDeletionLimited: utils.GetPtr(true), Hooks: []*models.Hook{{URL: utils.GetPtr("https://example.com")}}}

	actual := toOrganization(&github.Organization{Name: &orgName, MembersCanCreatePrivateRepos: utils.GetPtr(true)}, []*models.Hook{{URL: utils.GetPtr("https://example.com")}})

	assert.Equal(t, excepted, *actual)
}

func TestToPipeline(t *testing.T) {
	excepted := &pipelineParserModels.Pipeline{
		Name: utils.GetPtr("pipeline1"),
		Jobs: []*pipelineParserModels.Job{
			{
				ID:   utils.GetPtr("build"),
				Name: utils.GetPtr("Build"),
				Steps: []*pipelineParserModels.Step{
					{
						Name: utils.GetPtr("checkout"),
						Type: "task",
						Task: &pipelineParserModels.Task{
							Name:        utils.GetPtr("checkout"),
							Version:     utils.GetPtr("v1"),
							VersionType: "tag",
						},
						FileReference: &pipelineParserModels.FileReference{
							StartRef: &pipelineParserModels.FileLocation{
								Line:   8,
								Column: 9,
							},
							EndRef: &pipelineParserModels.FileLocation{
								Line:   9,
								Column: 26,
							},
						},
					},
				},
				FileReference: &pipelineParserModels.FileReference{
					StartRef: &pipelineParserModels.FileLocation{
						Line:   5,
						Column: 3,
					},
					EndRef: &pipelineParserModels.FileLocation{
						Line:   9,
						Column: 26,
					},
				},
				ContinueOnError: utils.GetPtr(false),
				TimeoutMS:       utils.GetPtr(21600000),
			},
		},
	}
	actual, err := toPipeline([]byte("name: pipeline1\n\n\njobs:\n  build:\n    name: Build\n    steps:  \n      - name: checkout\n        uses: checkout@v1"))
	assert.NoError(t, err)
	assert.Equal(t, excepted, actual)
}

func TestToUsers(t *testing.T) {
	login := "liorvais"
	permissions := make(map[string]bool)
	var excepted = models.User{Login: &login, Permissions: &permissions}

	actual := toUsers([]*github.User{{Login: &login, Permissions: permissions}})

	assert.Equal(t, excepted, *actual[0])
}

func TestPatchAdmins(t *testing.T) {
	login := "liorvais"
	var allMembers = []*models.User{{Login: &login}}
	var admins = []*models.User{{Login: &login}}
	var excepted = []*models.User{{Login: &login, Role: "admin"}}

	actual := patchAdminRoles(allMembers, admins)
	assert.Equal(t, excepted, actual)
}

func TestToPackages(t *testing.T) {
	var packages = []*github.Package{{Visibility: utils.GetPtr("private"), PackageType: utils.GetPtr("npm")}}
	var excepted = []*models.Package{{Visibility: utils.GetPtr("private"), PackageType: utils.GetPtr("npm")}}

	actual := toPackages(packages)
	assert.Equal(t, excepted, actual)
}

func TestToRegistry(t *testing.T) {
	var org = &models.Organization{TwoFactorRequirementEnabled: utils.GetPtr(true)}
	var excepted = &models.PackageRegistry{Packages: toPackages([]*github.Package{{Visibility: utils.GetPtr("private")}}), TwoFactorRequirementEnabled: utils.GetPtr(true)}

	actual := toRegistry([]*github.Package{{Visibility: utils.GetPtr("private")}}, org.TwoFactorRequirementEnabled)
	assert.Equal(t, excepted, actual)
}

func TestToBranchProtection(t *testing.T) {
	requiredStatusCheck := &models.RequiredStatusChecks{Strict: true}
	excepted := models.Protection{RequiredStatusChecks: requiredStatusCheck, EnforceAdmins: &models.AdminEnforcement{}}
	actual := toBranchProtection(&github.Protection{RequiredStatusChecks: &github.RequiredStatusChecks{Strict: true}}, &github.SignaturesProtectedBranch{})

	assert.Equal(t, excepted, *actual)
}
