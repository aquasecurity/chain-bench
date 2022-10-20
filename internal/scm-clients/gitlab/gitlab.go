package gitlab

import (
	"context"
	"fmt"
	"net/http"

	"github.com/xanzy/go-gitlab"
)

var (
	Client GitlabClient
)

type GitlabClient interface {
	GetAuthorizedUser() (*gitlab.User, *gitlab.Response, error)
	//ListOrganizationMembers(organization string, options *gitlab.ListGroupMembersOptions) ([]*gitlab.User, *gitlab.Response, error)
	ListRepositoryBranches(org string, repoId string) ([]*gitlab.Branch, *gitlab.Response, error)
	//GetRepositoryBranch(owner, repo, branch string, followRedirects bool) (*gitlab.Branch, *gitlab.Response, error)
	//GetCommit(organization string, repositoryName string, sha string) (*gitlab.Commit, *gitlab.Response, error)
	//ListCommits(organization string, repositoryName string, opts *gitlab.CommitActionOptions) ([]*gitlab.Commit, *gitlab.Response, error)
	GetBranchProtection(owner string, repo string, branch string) (*gitlab.ProtectedBranch, *gitlab.Response, error)
	GetApprovalConfiguration(project string) (*gitlab.ProjectApprovals, *gitlab.Response, error)
	GetProjectApprovalRules(project string) ([]*gitlab.ProjectApprovalRule, *gitlab.Response, error)
	GetProjectPushRules(project string) (*gitlab.ProjectPushRules, *gitlab.Response, error)
	// GetSignaturesOfProtectedBranch(owner, repo, branch string) (*gitlab.SignaturesProtectedBranch, *gitlab.Response, error)
	// ListRepositoryCollaborators(owner string, repo string) ([]*gitlab.User, *gitlab.Response, error)
	// ListPullRequestsWithCommit(owner, repository, sha string, opts *gitlab.PullRequestListOptions) ([]*gitlab.PullRequest, *gitlab.Response, error)
	// ListPullRequestReviews(owner, repo string, number int, opts *gitlab.ListOptions) ([]*gitlab.PullRequestReview, *gitlab.Response, error)
	// ListRepositoryTopics(owner, repo string) ([]string, *gitlab.Response, error)
	// ListPullRequestCommits(owner string, repo string, number int, opts *gitlab.ListOptions) ([]*gitlab.RepositoryCommit, *gitlab.Response, error)
	GetRepository(owner, repo string) (*gitlab.Project, *gitlab.Response, error)
	GetOrganization(owner string) (*gitlab.Group, *gitlab.Response, error)
	// GetWorkflows(owner, repo string) (*gitlab.Workflows, *gitlab.Response, error)
	// GetContent(owner, repo, filepath, ref string) (fileContent *gitlab.RepositoryContent, directoryContent []*gitlab.RepositoryContent, resp *gitlab.Response, err error)
	// ListOrganizationHooks(owner string) (hooks []*gitlab.Hook, resp *gitlab.Response, err error)
	// ListRepositoryHooks(owner, repo string) (hooks []*gitlab.Hook, resp *gitlab.Response, err error)
	// ListOrganizationPackages(owner string, packageType string) ([]*gitlab.Package, *gitlab.Response, error)
}

type gitlabClientImpl struct {
	ctx    context.Context
	client *gitlab.Client
}

//var _ gitlabClient = (*gitlabClientImpl)(nil) // Verify that *gitlabClientImpl implements gitlabClient.

func InitClient(client *http.Client, token string) (GitlabClient, error) {
	gc, _ := gitlab.NewClient(token, gitlab.WithHTTPClient(client))
	Client = &gitlabClientImpl{ctx: context.TODO(), client: gc}
	return Client, nil
}

func (gca *gitlabClientImpl) GetAuthorizedUser() (*gitlab.User, *gitlab.Response, error) {
	return gca.client.Users.GetUser(1, gitlab.GetUsersOptions{})
}

// func (gca *gitlabClientImpl) ListOrganizationMembers(organization string, opts *gitlab.ListGroupMembersOptions) ([]*gitlab.User, *gitlab.Response, error) {
// 	return gca.client.Groups.ListAllGroupMembers().ListMembers(gca.ctx, organization, opts)
// }

func (gca *gitlabClientImpl) ListRepositoryBranches(org string, repoId string) ([]*gitlab.Branch, *gitlab.Response, error) {
	return gca.client.Branches.ListBranches(repoId, &gitlab.ListBranchesOptions{})
}

// func (gca *gitlabClientImpl) GetCommit(organization string, repositoryName string, sha string) (*gitlab.RepositoryCommit, *gitlab.Response, error) {
// 	return gca.client.Repositories.GetCommit(gca.ctx, organization, repositoryName, sha, &gitlab.ListOptions{})
// }

// func (gca *gitlabClientImpl) ListCommits(organization string, repositoryName string, opts *gitlab.CommitsListOptions) ([]*gitlab.RepositoryCommit, *gitlab.Response, error) {
// 	return gca.client.Repositories.ListCommits(gca.ctx, organization, repositoryName, opts)
// }

// func (gca *gitlabClientImpl) GetRepositoryBranch(organization, repositoryName, branch string, followRedirects bool) (*gitlab.Branch, *gitlab.Response, error) {
// 	return gca.client.Repositories.GetBranch(gca.ctx, organization, repositoryName, branch, false)
// }

func (gca *gitlabClientImpl) GetBranchProtection(organization, repo, branch string) (*gitlab.ProtectedBranch, *gitlab.Response, error) {
	return gca.client.ProtectedBranches.GetProtectedBranch(repo, branch)
}

func (gca *gitlabClientImpl) GetApprovalConfiguration(project string) (*gitlab.ProjectApprovals, *gitlab.Response, error) {
	return gca.client.Projects.GetApprovalConfiguration(project)
}

func (gca *gitlabClientImpl) GetProjectApprovalRules(project string) ([]*gitlab.ProjectApprovalRule, *gitlab.Response, error) {
	return gca.client.Projects.GetProjectApprovalRules(project)
}

func (gca *gitlabClientImpl) GetProjectPushRules(project string) (*gitlab.ProjectPushRules, *gitlab.Response, error) {
	return gca.client.Projects.GetProjectPushRules(project)
}

// func (gca *gitlabClientImpl) GetSignaturesOfProtectedBranch(owner, repo, branch string) (*gitlab.SignaturesProtectedBranch, *gitlab.Response, error) {
// 	return gca.client.Repositories.GetSignaturesProtectedBranch(gca.ctx, owner, repo, branch)
// }

// func (gca *gitlabClientImpl) ListRepositoryCollaborators(owner, repo string) ([]*gitlab.User, *gitlab.Response, error) {
// 	return gca.client.Repositories.ListCollaborators(gca.ctx, owner, repo, nil)
// }

// func (gca *gitlabClientImpl) ListPullRequestsWithCommit(owner, repository, sha string, opts *gitlab.PullRequestListOptions) ([]*gitlab.PullRequest, *gitlab.Response, error) {
// 	return gca.client.PullRequests.ListPullRequestsWithCommit(gca.ctx, owner, repository, sha, opts)
// }

// func (gca *gitlabClientImpl) ListPullRequestReviews(owner, repo string, number int, opts *gitlab.ListOptions) ([]*gitlab.PullRequestReview, *gitlab.Response, error) {
// 	return gca.client.PullRequests.ListReviews(gca.ctx, owner, repo, number, opts)
// }

// func (gca *gitlabClientImpl) ListRepositoryTopics(owner, repo string) ([]string, *gitlab.Response, error) {
// 	return gca.client.Repositories.ListAllTopics(gca.ctx, owner, repo)
// }

// func (gca *gitlabClientImpl) ListPullRequestCommits(owner string, repo string, number int, opts *gitlab.ListOptions) ([]*gitlab.RepositoryCommit, *gitlab.Response, error) {
// 	return gca.client.PullRequests.ListCommits(gca.ctx, owner, repo, number, opts)
// }

func (gca *gitlabClientImpl) GetRepository(owner, repo string) (*gitlab.Project, *gitlab.Response, error) {
	return gca.client.Projects.GetProject(fmt.Sprintf("%s/%s", owner, repo), &gitlab.GetProjectOptions{})
}

func (gca *gitlabClientImpl) GetOrganization(owner string) (*gitlab.Group, *gitlab.Response, error) {
	return gca.client.Groups.GetGroup(owner, &gitlab.GetGroupOptions{})
}

// func (gca *gitlabClientImpl) GetWorkflows(owner, repo string) (*gitlab.Workflows, *gitlab.Response, error) {
// 	return gca.client.Actions.ListWorkflows(gca.ctx, owner, repo, nil)
// }

// func (gca *gitlabClientImpl) GetContent(owner, repo, filepath, ref string) (fileContent *gitlab.RepositoryContent, directoryContent []*gitlab.RepositoryContent, resp *gitlab.Response, err error) {
// 	return gca.client.Repositories.GetContents(gca.ctx, owner, repo, filepath, &gitlab.RepositoryContentGetOptions{Ref: ref})
// }

// //need admin:repo_hook->read:repo_hook
// func (gca *gitlabClientImpl) ListRepositoryHooks(owner, repo string) (hooks []*gitlab.Hook, resp *gitlab.Response, err error) {
// 	return gca.client.Repositories.ListHooks(gca.ctx, owner, repo, nil)
// }

// //need admin:org_hook
// func (gca *gitlabClientImpl) ListOrganizationHooks(owner string) (hooks []*gitlab.Hook, resp *gitlab.Response, err error) {
// 	return gca.client.Organizations.ListHooks(gca.ctx, owner, nil)
// }

// //need read:packages
// func (gca *gitlabClientImpl) ListOrganizationPackages(owner string, packageType string) ([]*gitlab.Package, *gitlab.Response, error) {
// 	return gca.client.Organizations.ListPackages(gca.ctx, owner, &gitlab.PackageListOptions{State: utils.GetPtr("active"), PackageType: &packageType})
// }
