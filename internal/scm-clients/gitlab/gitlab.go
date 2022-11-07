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
	ListRepositoryBranches(org string, repoId string) ([]*gitlab.Branch, *gitlab.Response, error)
	GetBranchProtection(owner string, repo string, branch string) (*gitlab.ProtectedBranch, *gitlab.Response, error)
	GetApprovalConfiguration(project string) (*gitlab.ProjectApprovals, *gitlab.Response, error)
	GetProjectApprovalRules(project string) ([]*gitlab.ProjectApprovalRule, *gitlab.Response, error)
	GetProjectPushRules(project string) (*gitlab.ProjectPushRules, *gitlab.Response, error)
	GetRepository(owner, repo string) (*gitlab.Project, *gitlab.Response, error)
	GetOrganization(owner string) (*gitlab.Group, *gitlab.Response, error)
}

type GitlabClientImpl struct {
	ctx    context.Context
	client *gitlab.Client
}

var _ GitlabClient = (*GitlabClientImpl)(nil) // Verify that *GitlabClientImpl implements gitlabClient.

func InitClient(client *http.Client, token string, host string) (GitlabClient, error) {
	var gc *gitlab.Client
	if host == "gitlab.com" {
		gc, _ = gitlab.NewClient(token, gitlab.WithHTTPClient(client))
	} else {
		gc, _ = gitlab.NewClient(token, gitlab.WithHTTPClient(client), gitlab.WithBaseURL(fmt.Sprintf("https://%s/api/v4", host)))
	}
	Client = &GitlabClientImpl{ctx: context.TODO(), client: gc}
	return Client, nil
}
func (gca *GitlabClientImpl) GetAuthorizedUser() (*gitlab.User, *gitlab.Response, error) {
	return gca.client.Users.GetUser(1, gitlab.GetUsersOptions{})
}

func (gca *GitlabClientImpl) ListRepositoryBranches(org string, repoId string) ([]*gitlab.Branch, *gitlab.Response, error) {
	return gca.client.Branches.ListBranches(repoId, &gitlab.ListBranchesOptions{})
}

func (gca *GitlabClientImpl) GetBranchProtection(organization, repo, branch string) (*gitlab.ProtectedBranch, *gitlab.Response, error) {
	return gca.client.ProtectedBranches.GetProtectedBranch(repo, branch)
}

func (gca *GitlabClientImpl) GetApprovalConfiguration(project string) (*gitlab.ProjectApprovals, *gitlab.Response, error) {
	return gca.client.Projects.GetApprovalConfiguration(project)
}

func (gca *GitlabClientImpl) GetProjectApprovalRules(project string) ([]*gitlab.ProjectApprovalRule, *gitlab.Response, error) {
	return gca.client.Projects.GetProjectApprovalRules(project)
}

func (gca *GitlabClientImpl) GetProjectPushRules(project string) (*gitlab.ProjectPushRules, *gitlab.Response, error) {
	return gca.client.Projects.GetProjectPushRules(project)
}

func (gca *GitlabClientImpl) GetRepository(owner, repo string) (*gitlab.Project, *gitlab.Response, error) {
	return gca.client.Projects.GetProject(fmt.Sprintf("%s/%s", owner, repo), &gitlab.GetProjectOptions{})
}

func (gca *GitlabClientImpl) GetOrganization(owner string) (*gitlab.Group, *gitlab.Response, error) {
	return gca.client.Groups.GetGroup(owner, &gitlab.GetGroupOptions{})
}
