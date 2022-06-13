package github

import "github.com/google/go-github/v41/github"

type MockGithubClientAdapter struct {
}

var (
	ListMembersFunc                    func(organization string, options github.ListMembersOptions) ([]*github.User, error)
	GetBranchFunc                      func(owner, repo, branch string, followRedirects bool) (*github.Branch, error)
	ListOrganizationMembersFunc        func(organization string, options *github.ListMembersOptions) ([]*github.User, *github.Response, error)
	GetRepositoryBranchFunc            func(owner, repo, branch string, followRedirects bool) (*github.Branch, *github.Response, error)
	ListRepositoryBranchesFunc         func(owner string, repo string) ([]*github.Branch, *github.Response, error)
	GetAuthorizedUserFunc              func() (*github.User, *github.Response, error)
	GetCommitFunc                      func(organization string, repositoryName string, sha string) (*github.RepositoryCommit, *github.Response, error)
	ListCommitsFunc                    func(organization string, repositoryName string, opts *github.CommitsListOptions) ([]*github.RepositoryCommit, *github.Response, error)
	GetBranchProtectionFunc            func(owner, repo, branch string) (*github.Protection, *github.Response, error)
	GetSignaturesOfProtectedBranchFunc func(owner, repo, branch string) (*github.SignaturesProtectedBranch, *github.Response, error)
	ListPullRequestsWithCommitFunc     func(owner, repository, sha string, opts *github.PullRequestListOptions) ([]*github.PullRequest, *github.Response, error)
	ListPullRequestReviewsFunc         func(owner, repo string, number int, opts *github.ListOptions) ([]*github.PullRequestReview, *github.Response, error)
	ListRepositoryTopicsFunc           func(owner, repo string) ([]string, *github.Response, error)
	ListPullRequestCommitsFunc         func(owner string, repo string, number int, opts *github.ListOptions) ([]*github.RepositoryCommit, *github.Response, error)
	ListRepositoryCollaboratorsFunc    func(owner string, repo string) ([]*github.User, *github.Response, error)
	GetRepositoryFunc                  func(owner, repo string) (*github.Repository, *github.Response, error)
	GetOrganizationFunc                func(orgName string) (*github.Organization, *github.Response, error)
	GetWorkflowsFunc                   func(owner, repo string) (*github.Workflows, *github.Response, error)
	GetContentFunc                     func(owner, repo, path string, ref string) (*github.RepositoryContent, []*github.RepositoryContent, *github.Response, error)
	ListOrganizationHooksFunc          func(owner string) (hooks []*github.Hook, resp *github.Response, err error)
	ListRepositoryHooksFunc            func(owner, repo string) (hooks []*github.Hook, resp *github.Response, err error)
	ListOrganizationPackagesFunc       func(owner string, packagetype string) ([]*github.Package, *github.Response, error)
)

func InitMocks() GithubClient {
	Client = &MockGithubClientAdapter{}
	return Client
}

func (mgca *MockGithubClientAdapter) ListMembers(organization string, options github.ListMembersOptions) ([]*github.User, error) {
	if ListMembersFunc != nil {
		return ListMembersFunc(organization, options)
	}

	return []*github.User{}, nil
}

func (mgca *MockGithubClientAdapter) GetBranch(owner, repo, branch string, followRedirects bool) (*github.Branch, error) {
	if GetBranchFunc != nil {
		return GetBranchFunc(owner, repo, branch, followRedirects)
	}

	return &github.Branch{}, nil
}

func (mgca *MockGithubClientAdapter) ListOrganizationMembers(organization string, options *github.ListMembersOptions) ([]*github.User, *github.Response, error) {
	if ListOrganizationMembersFunc != nil {
		return ListOrganizationMembersFunc(organization, options)
	}

	return []*github.User{}, nil, nil
}

func (mgca *MockGithubClientAdapter) ListRepositoryCollaborators(owner string, repo string) ([]*github.User, *github.Response, error) {
	if ListOrganizationMembersFunc != nil {
		return ListRepositoryCollaboratorsFunc(owner, repo)
	}

	return []*github.User{}, nil, nil
}

func (mgca *MockGithubClientAdapter) GetRepositoryBranch(owner, repo, branch string, followRedirects bool) (*github.Branch, *github.Response, error) {
	if GetRepositoryBranchFunc != nil {
		return GetRepositoryBranchFunc(owner, repo, branch, followRedirects)
	}

	return &github.Branch{}, nil, nil
}

func (mgca *MockGithubClientAdapter) GetCommit(organization string, repositoryName string, sha string) (*github.RepositoryCommit, *github.Response, error) {
	if GetCommitFunc != nil {
		return GetCommitFunc(organization, repositoryName, sha)
	}

	return &github.RepositoryCommit{}, nil, nil
}

func (mgca *MockGithubClientAdapter) ListCommits(organization string, repositoryName string, opts *github.CommitsListOptions) ([]*github.RepositoryCommit, *github.Response, error) {
	if ListCommitsFunc != nil {
		return ListCommitsFunc(organization, repositoryName, opts)
	}

	return []*github.RepositoryCommit{}, nil, nil
}

func (mgca *MockGithubClientAdapter) ListRepositoryBranches(owner, repo string) ([]*github.Branch, *github.Response, error) {
	if GetRepositoryBranchFunc != nil {
		return ListRepositoryBranchesFunc(owner, repo)
	}

	return []*github.Branch{}, nil, nil
}

func (mgca *MockGithubClientAdapter) GetAuthorizedUser() (*github.User, *github.Response, error) {
	if GetRepositoryBranchFunc != nil {
		return GetAuthorizedUserFunc()
	}

	return &github.User{}, nil, nil
}

func (*MockGithubClientAdapter) GetBranchProtection(owner string, repo string, branch string) (*github.Protection, *github.Response, error) {
	if GetBranchProtectionFunc != nil {
		return GetBranchProtectionFunc(owner, repo, branch)
	}
	return &github.Protection{}, nil, nil
}

func (*MockGithubClientAdapter) GetSignaturesOfProtectedBranch(owner string, repo string, branch string) (*github.SignaturesProtectedBranch, *github.Response, error) {
	if GetBranchProtectionFunc != nil {
		return GetSignaturesOfProtectedBranchFunc(owner, repo, branch)
	}
	return &github.SignaturesProtectedBranch{}, nil, nil
}

func (mgca *MockGithubClientAdapter) ListPullRequestsWithCommit(owner, repository, sha string, opts *github.PullRequestListOptions) ([]*github.PullRequest, *github.Response, error) {
	if ListPullRequestsWithCommitFunc != nil {
		return ListPullRequestsWithCommitFunc(owner, repository, sha, opts)
	}

	return []*github.PullRequest{}, nil, nil
}

func (mgca *MockGithubClientAdapter) ListPullRequestReviews(owner, repo string, number int, opts *github.ListOptions) ([]*github.PullRequestReview, *github.Response, error) {
	if ListPullRequestReviewsFunc != nil {
		return ListPullRequestReviewsFunc(owner, repo, number, opts)
	}

	return []*github.PullRequestReview{}, nil, nil
}

func (mgca *MockGithubClientAdapter) ListRepositoryTopics(owner, repo string) ([]string, *github.Response, error) {
	if ListRepositoryTopicsFunc != nil {
		return ListRepositoryTopicsFunc(owner, repo)
	}

	return []string{}, nil, nil
}

func (mgca *MockGithubClientAdapter) ListPullRequestCommits(owner string, repo string, number int, opts *github.ListOptions) ([]*github.RepositoryCommit, *github.Response, error) {
	if ListPullRequestCommitsFunc != nil {
		return ListPullRequestCommitsFunc(owner, repo, number, opts)
	}

	return []*github.RepositoryCommit{}, nil, nil
}

func (mgca *MockGithubClientAdapter) GetRepository(owner, repo string) (*github.Repository, *github.Response, error) {
	if GetRepositoryFunc != nil {
		return GetRepositoryFunc(owner, repo)
	}

	return &github.Repository{}, nil, nil
}

func (mgca *MockGithubClientAdapter) GetOrganization(orgName string) (*github.Organization, *github.Response, error) {
	if GetOrganizationFunc != nil {
		return GetOrganizationFunc(orgName)
	}

	return &github.Organization{}, nil, nil
}

func (mgca *MockGithubClientAdapter) GetWorkflows(owner, repo string) (*github.Workflows, *github.Response, error) {
	if GetWorkflowsFunc != nil {
		return GetWorkflowsFunc(owner, repo)
	}

	return &github.Workflows{}, nil, nil
}

func (mgca *MockGithubClientAdapter) GetContent(owner, repo, path, ref string) (*github.RepositoryContent, []*github.RepositoryContent, *github.Response, error) {
	if GetContentFunc != nil {
		return GetContentFunc(owner, repo, path, ref)
	}
	return &github.RepositoryContent{}, nil, nil, nil
}

func (mgca *MockGithubClientAdapter) ListOrganizationHooks(owner string) ([]*github.Hook, *github.Response, error) {
	if ListOrganizationHooksFunc != nil {
		return ListOrganizationHooksFunc(owner)
	}

	return []*github.Hook{}, nil, nil
}

func (mgca *MockGithubClientAdapter) ListRepositoryHooks(owner, repo string) ([]*github.Hook, *github.Response, error) {
	if ListRepositoryHooksFunc != nil {
		return ListRepositoryHooksFunc(owner, repo)
	}

	return []*github.Hook{}, nil, nil
}

func (mgca *MockGithubClientAdapter) ListOrganizationPackages(owner string, packagetype string) ([]*github.Package, *github.Response, error) {
	if ListOrganizationPackagesFunc != nil {
		return ListOrganizationPackagesFunc(owner, packagetype)
	}

	return []*github.Package{}, nil, nil
}
