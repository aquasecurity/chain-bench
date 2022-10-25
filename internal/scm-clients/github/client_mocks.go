package github

import (
	"github.com/google/go-github/v41/github"
	"github.com/migueleliasweb/go-github-mock/src/mock"
)

func MockGetRepo(repo *github.Repository) *GithubClient {
	mockedHTTPClient := mock.NewMockedHTTPClient(
		mock.WithRequestMatch(
			mock.GetReposByOwnerByRepo,
			*repo,
		),
	)
	gc, _ := InitClient(mockedHTTPClient,"")
	return &gc
}

func MockGetBranchProtections(protection *github.Protection) *GithubClient {
	mockedHTTPClient := mock.NewMockedHTTPClient(
		mock.WithRequestMatch(
			mock.GetReposBranchesProtectionByOwnerByRepoByBranch,
			*protection,
		),
	)
	gc, _ := InitClient(mockedHTTPClient, "")
	return &gc
}

func MockGetSignaturesOfProtectedBranch(signedCommits *github.SignaturesProtectedBranch) *GithubClient {
	mockedHTTPClient := mock.NewMockedHTTPClient(
		mock.WithRequestMatch(
			mock.GetReposBranchesProtectionRequiredSignaturesByOwnerByRepoByBranch,
			*signedCommits,
		),
	)
	gc, _ := InitClient(mockedHTTPClient, "")
	return &gc
}

func MockGetOrganization(org *github.Organization) *GithubClient {
	mockedHTTPClient := mock.NewMockedHTTPClient(
		mock.WithRequestMatch(
			mock.GetOrgsByOrg,
			*org,
		),
	)
	gc, _ := InitClient(mockedHTTPClient, "")
	return &gc
}

func MockGetOrganizationMembers(users []*github.User) *GithubClient {
	mockedHTTPClient := mock.NewMockedHTTPClient(
		mock.WithRequestMatch(
			mock.GetOrgsMembersByOrg,
			users,
		),
	)
	gc, _ := InitClient(mockedHTTPClient, "")
	return &gc
}

func MockGetWorkflows(workflows *github.Workflows) *GithubClient {
	mockedHTTPClient := mock.NewMockedHTTPClient(
		mock.WithRequestMatch(
			mock.GetReposActionsWorkflowsByOwnerByRepo,
			workflows,
		),
	)
	gc, _ := InitClient(mockedHTTPClient, "")
	return &gc
}

func MockGetContent(content *github.RepositoryContent) *GithubClient {
	mockedHTTPClient := mock.NewMockedHTTPClient(
		mock.WithRequestMatch(
			mock.GetReposContentsByOwnerByRepoByPath,
			content,
		),
	)
	gc, _ := InitClient(mockedHTTPClient, "")
	return &gc
}

func MockGetOrganizationWebhooks(hooks []*github.Hook) *GithubClient {
	mockedHTTPClient := mock.NewMockedHTTPClient(
		mock.WithRequestMatch(
			mock.GetOrgsHooksByOrg,
			hooks,
		),
	)
	gc, _ := InitClient(mockedHTTPClient, "")
	return &gc
}

func MockGetRepositoryWebhooks(hooks []*github.Hook) *GithubClient {
	mockedHTTPClient := mock.NewMockedHTTPClient(
		mock.WithRequestMatch(
			mock.GetReposHooksByOwnerByRepo,
			hooks,
		),
	)
	gc, _ := InitClient(mockedHTTPClient, "")
	return &gc
}

func MockListCommits(commits []*github.RepositoryCommit) *GithubClient {
	mockedHTTPClient := mock.NewMockedHTTPClient(
		mock.WithRequestMatch(
			mock.GetReposCommitsByOwnerByRepo,
			commits,
		),
	)
	gc, _ := InitClient(mockedHTTPClient, "")
	return &gc
}

func MockListOrganizationPackages(packages []*github.Package) *GithubClient {
	mockedHTTPClient := mock.NewMockedHTTPClient(
		mock.WithRequestMatch(
			mock.GetOrgsPackagesByOrg,
			packages,
		),
	)
	gc, _ := InitClient(mockedHTTPClient, "")
	return &gc
}
