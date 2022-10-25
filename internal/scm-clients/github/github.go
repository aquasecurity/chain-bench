package github

import (
	"context"
	"net/http"

	"github.com/aquasecurity/chain-bench/internal/utils"
	"github.com/google/go-github/v41/github"
)

var (
	Client GithubClient
)

type GithubClient interface {
	GetAuthorizedUser() (*github.User, *github.Response, error)
	ListOrganizationMembers(organization string, options *github.ListMembersOptions) ([]*github.User, *github.Response, error)
	ListRepositoryBranches(organization string, repositoryName string) ([]*github.Branch, *github.Response, error)
	GetRepositoryBranch(owner, repo, branch string, followRedirects bool) (*github.Branch, *github.Response, error)
	GetCommit(organization string, repositoryName string, sha string) (*github.RepositoryCommit, *github.Response, error)
	ListCommits(organization string, repositoryName string, opts *github.CommitsListOptions) ([]*github.RepositoryCommit, *github.Response, error)
	GetBranchProtection(owner string, repo string, branch string) (*github.Protection, *github.Response, error)
	GetSignaturesOfProtectedBranch(owner, repo, branch string) (*github.SignaturesProtectedBranch, *github.Response, error)
	ListRepositoryCollaborators(owner string, repo string) ([]*github.User, *github.Response, error)
	ListPullRequestsWithCommit(owner, repository, sha string, opts *github.PullRequestListOptions) ([]*github.PullRequest, *github.Response, error)
	ListPullRequestReviews(owner, repo string, number int, opts *github.ListOptions) ([]*github.PullRequestReview, *github.Response, error)
	ListRepositoryTopics(owner, repo string) ([]string, *github.Response, error)
	ListPullRequestCommits(owner string, repo string, number int, opts *github.ListOptions) ([]*github.RepositoryCommit, *github.Response, error)
	GetRepository(owner, repo string) (*github.Repository, *github.Response, error)
	GetOrganization(owner string) (*github.Organization, *github.Response, error)
	GetWorkflows(owner, repo string) (*github.Workflows, *github.Response, error)
	GetContent(owner, repo, filepath, ref string) (fileContent *github.RepositoryContent, directoryContent []*github.RepositoryContent, resp *github.Response, err error)
	ListOrganizationHooks(owner string) (hooks []*github.Hook, resp *github.Response, err error)
	ListRepositoryHooks(owner, repo string) (hooks []*github.Hook, resp *github.Response, err error)
	ListOrganizationPackages(owner string, packageType string) ([]*github.Package, *github.Response, error)
}

type GithubClientImpl struct {
	ctx    context.Context
	client *github.Client
}

var _ GithubClient = (*GithubClientImpl)(nil) // Verify that *GithubClientImpl implements GithubClient.

func InitClient(client *http.Client, token string) (GithubClient, error) {
	gc := github.NewClient(client)
	Client = &GithubClientImpl{ctx: context.TODO(), client: gc}
	return Client, nil
}

func (gca *GithubClientImpl) ListOrganizationMembers(organization string, opts *github.ListMembersOptions) ([]*github.User, *github.Response, error) {
	return gca.client.Organizations.ListMembers(gca.ctx, organization, opts)
}

func (gca *GithubClientImpl) ListRepositoryBranches(organization string, repositoryName string) ([]*github.Branch, *github.Response, error) {
	return gca.client.Repositories.ListBranches(gca.ctx, organization, repositoryName, &github.BranchListOptions{})
}

func (gca *GithubClientImpl) GetCommit(organization string, repositoryName string, sha string) (*github.RepositoryCommit, *github.Response, error) {
	return gca.client.Repositories.GetCommit(gca.ctx, organization, repositoryName, sha, &github.ListOptions{})
}

func (gca *GithubClientImpl) ListCommits(organization string, repositoryName string, opts *github.CommitsListOptions) ([]*github.RepositoryCommit, *github.Response, error) {
	return gca.client.Repositories.ListCommits(gca.ctx, organization, repositoryName, opts)
}

func (gca *GithubClientImpl) GetRepositoryBranch(organization, repositoryName, branch string, followRedirects bool) (*github.Branch, *github.Response, error) {
	return gca.client.Repositories.GetBranch(gca.ctx, organization, repositoryName, branch, false)
}

func (gca *GithubClientImpl) GetBranchProtection(organization, repo, branch string) (*github.Protection, *github.Response, error) {
	return gca.client.Repositories.GetBranchProtection(gca.ctx, organization, repo, branch)
}

func (gca *GithubClientImpl) GetSignaturesOfProtectedBranch(owner, repo, branch string) (*github.SignaturesProtectedBranch, *github.Response, error) {
	return gca.client.Repositories.GetSignaturesProtectedBranch(gca.ctx, owner, repo, branch)
}

func (gca *GithubClientImpl) ListRepositoryCollaborators(owner, repo string) ([]*github.User, *github.Response, error) {
	return gca.client.Repositories.ListCollaborators(gca.ctx, owner, repo, nil)
}

func (gca *GithubClientImpl) ListPullRequestsWithCommit(owner, repository, sha string, opts *github.PullRequestListOptions) ([]*github.PullRequest, *github.Response, error) {
	return gca.client.PullRequests.ListPullRequestsWithCommit(gca.ctx, owner, repository, sha, opts)
}

func (gca *GithubClientImpl) ListPullRequestReviews(owner, repo string, number int, opts *github.ListOptions) ([]*github.PullRequestReview, *github.Response, error) {
	return gca.client.PullRequests.ListReviews(gca.ctx, owner, repo, number, opts)
}

func (gca *GithubClientImpl) GetAuthorizedUser() (*github.User, *github.Response, error) {
	return gca.client.Users.Get(gca.ctx, "")
}

func (gca *GithubClientImpl) ListRepositoryTopics(owner, repo string) ([]string, *github.Response, error) {
	return gca.client.Repositories.ListAllTopics(gca.ctx, owner, repo)
}

func (gca *GithubClientImpl) ListPullRequestCommits(owner string, repo string, number int, opts *github.ListOptions) ([]*github.RepositoryCommit, *github.Response, error) {
	return gca.client.PullRequests.ListCommits(gca.ctx, owner, repo, number, opts)
}

func (gca *GithubClientImpl) GetRepository(owner, repo string) (*github.Repository, *github.Response, error) {
	return gca.client.Repositories.Get(gca.ctx, owner, repo)
}

func (gca *GithubClientImpl) GetOrganization(owner string) (*github.Organization, *github.Response, error) {
	return gca.client.Organizations.Get(gca.ctx, owner)
}

func (gca *GithubClientImpl) GetWorkflows(owner, repo string) (*github.Workflows, *github.Response, error) {
	return gca.client.Actions.ListWorkflows(gca.ctx, owner, repo, nil)
}

func (gca *GithubClientImpl) GetContent(owner, repo, filepath, ref string) (fileContent *github.RepositoryContent, directoryContent []*github.RepositoryContent, resp *github.Response, err error) {
	return gca.client.Repositories.GetContents(gca.ctx, owner, repo, filepath, &github.RepositoryContentGetOptions{Ref: ref})
}

//need admin:repo_hook->read:repo_hook
func (gca *GithubClientImpl) ListRepositoryHooks(owner, repo string) (hooks []*github.Hook, resp *github.Response, err error) {
	return gca.client.Repositories.ListHooks(gca.ctx, owner, repo, nil)
}

//need admin:org_hook
func (gca *GithubClientImpl) ListOrganizationHooks(owner string) (hooks []*github.Hook, resp *github.Response, err error) {
	return gca.client.Organizations.ListHooks(gca.ctx, owner, nil)
}

//need read:packages
func (gca *GithubClientImpl) ListOrganizationPackages(owner string, packageType string) ([]*github.Package, *github.Response, error) {
	return gca.client.Organizations.ListPackages(gca.ctx, owner, &github.PackageListOptions{State: utils.GetPtr("active"), PackageType: &packageType})
}
