package github

import (
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/argonsecurity/chain-bench/internal/logger"
	"github.com/argonsecurity/chain-bench/internal/models"
	"github.com/argonsecurity/chain-bench/internal/scm-clients/adapter"
	"github.com/argonsecurity/chain-bench/internal/utils"
	pipelineModels "github.com/argonsecurity/pipeline-parser/pkg/models"
	"github.com/google/go-github/v41/github"
)

var (
	Adapter ClientAdapterImpl
)

type ClientAdapterImpl struct {
	client GithubClient
}

// Init implements clients.ClientAdapter
func (*ClientAdapterImpl) Init(client *http.Client) error {
	ghClient, err := InitClient(client)
	Adapter = ClientAdapterImpl{client: ghClient}
	return err
}

func (ca *ClientAdapterImpl) GetAuthorizedUser() (*models.User, error) {
	res, _, err := ca.client.GetAuthorizedUser()
	if err != nil {
		logger.Error(err, "error in authenticated user data")
		return nil, err
	}

	return toUser(res), nil
}

// GetRepository implements clients.ClientAdapter
func (ca *ClientAdapterImpl) GetRepository(owner string, repo string) (*models.Repository, error) {
	rep, _, err := ca.client.GetRepository(owner, repo)
	if err != nil {
		logger.Error(err, "error in fetching repository data")
		return nil, err
	}

	commits, _, err := ca.client.ListCommits(owner, repo, &github.CommitsListOptions{Since: time.Now().AddDate(0, -3, 0)})
	if err != nil {
		logger.Error(err, "error in fetching commits data")
	}

	branches, err := ca.ListRepositoryBranches(owner, repo)
	if err != nil {
		logger.Error(err, "error in fetching branches data")
	}

	isRepoContainsSecurityMD := ca.isRepositoryContainsSecurityMdFile(owner, repo, utils.GetValue(rep.DefaultBranch))

	collaborators, _, err := ca.client.ListRepositoryCollaborators(owner, repo)
	if err != nil {
		logger.Error(err, "error in fetching collaborators data")
	}

	hooks, _, err := ca.client.ListRepositoryHooks(owner, repo)
	if err != nil {
		logger.Error(err, "error in fetching hooks data")
	}

	return toRepository(rep, branches, toUsers(collaborators), toHooks(hooks), toCommits(commits), isRepoContainsSecurityMD), nil
}

//listRepositoryBranches implements clients.ClientAdapter
func (ca *ClientAdapterImpl) ListRepositoryBranches(owner string, repo string) ([]*models.Branch, error) {
	branches, _, err := ca.client.ListRepositoryBranches(owner, repo)
	if err != nil {
		logger.Error(err, "error in fetching branches")
		return nil, err
	}
	enhancedBranches := []*github.Branch{}

	for _, b := range branches {
		commit, _, err := ca.client.GetCommit(owner, repo, utils.GetValue(b.Commit.SHA))
		if err != nil {
			logger.Error(err, "error in fetching branches commit")
		} else {
			branch := &github.Branch{
				Name:      b.Name,
				Commit:    commit,
				Protected: b.Protected,
			}
			enhancedBranches = append(enhancedBranches, branch)
		}
	}
	return toBranches(enhancedBranches), nil
}

// isRepositoryContainsSecurityMdFile implements clients.ClientAdapter
func (ca *ClientAdapterImpl) isRepositoryContainsSecurityMdFile(owner, repo, defaultBranch string) bool {
	optionalSecurityMDNames := []string{"SECURITY.md", "security.md", "Security.md"}

	for _, optionalName := range optionalSecurityMDNames {
		securityMdFile, _, _, _ := ca.client.GetContent(owner, repo, optionalName, defaultBranch)
		if securityMdFile != nil {
			return true
		}
	}

	return false
}

// GetRepositoryBranch implements clients.ClientAdapter
func (ca *ClientAdapterImpl) GetCommit(owner string, repo string, sha string) (*models.RepositoryCommit, error) {
	commit, _, err := ca.client.GetCommit(owner, repo, sha)
	if err != nil {
		logger.Error(err, "error in fetching branch protection")
		return nil, err
	}
	return toCommit(commit), nil
}

// GetRepositoryBranch implements clients.ClientAdapter
func (ca *ClientAdapterImpl) GetBranchProtection(owner string, repo string, branch string) (*models.Protection, error) {
	prot, _, err := ca.client.GetBranchProtection(owner, repo, branch)
	if err != nil {
		logger.Error(err, "error in fetching branch protection")
		return nil, err
	}

	sc, _ , err := ca.client.GetSignaturesOfProtectedBranch(owner, repo, branch)
	if err != nil {
		logger.Error(err, "error in fetching commit signature protection")
	}
	return toBranchProtection(prot, sc), nil
}

func (ca *ClientAdapterImpl) GetOrganization(owner string) (*models.Organization, error) {
	org, _, err := ca.client.GetOrganization(owner)
	if err != nil {
		logger.Error(err, "error in fetching organization")
		return nil, err
	}
	hooks, _, err := ca.client.ListOrganizationHooks(owner)
	if err != nil {
		logger.Error(err, "error in fetching organization hooks")
	}
	return toOrganization(org, toHooks(hooks)), nil
}

func (ca *ClientAdapterImpl) ListOrganizationMembers(organization string) ([]*models.User, error) {
	allMembers, _, err := ca.client.ListOrganizationMembers(organization, nil)
	if err != nil {
		logger.Error(err, "error in fetching members")
		return nil, err
	}
	admins, _, err := ca.client.ListOrganizationMembers(organization, &github.ListMembersOptions{Role: "admin"})
	if err != nil {
		logger.Error(err, "error in fetching admins")
		return nil, err
	}
	return patchAdminRoles(toUsers(allMembers), toUsers(admins)), nil
}

func (ca *ClientAdapterImpl) GetRegistry(organization *models.Organization) (*models.PackageRegistry, error) {
	if organization == nil {
		return nil, errors.New("organization is nil")
	}
	packagesTypes := []string{"npm", "maven", "rubygems", "nuget", "docker", "container"}
	packages := []*github.Package{}

	for _, packageType := range packagesTypes {
		pkgs, _, err := ca.client.ListOrganizationPackages(*organization.Login, packageType)
		if err != nil {
			logger.Error(err, "error in fetching org packages")
			packages = nil
			break
		}
		packages = append(packages, pkgs...)
	}

	return toRegistry(packages, organization.TwoFactorRequirementEnabled), nil
}

func patchAdminRoles(allMembers []*models.User, admins []*models.User) []*models.User {
	for _, admin := range admins {
		for _, member := range allMembers {
			if *member.Login == *admin.Login {
				member.Role = "admin"
			}
		}
	}
	return allMembers
}

func (ca *ClientAdapterImpl) GetPipelines(owner string, repo string, branch string) ([]*pipelineModels.Pipeline, error) {
	workflows, _, err := ca.client.GetWorkflows(owner, repo)
	if err != nil {
		logger.Error(err, "error in fetching workflows")
		return nil, err
	}

	pipelines := make([]*pipelineModels.Pipeline, 0)
	for _, workflow := range workflows.Workflows {
		if *workflow.Path == "" {
			continue
		}
		buf, err := ca.GetFileContent(owner, repo, *workflow.Path, branch)
		if err != nil {
			return nil, err
		}

		if buf == nil {
			continue
		}

		pipeline, err := toPipeline(buf)
		if err != nil {
			return nil, err
		}
		pipelines = append(pipelines, pipeline)
	}
	return pipelines, nil
}

func (ca *ClientAdapterImpl) GetFileContent(owner string, repo string, filepath string, ref string) ([]byte, error) {
	file, _, res, err := ca.client.GetContent(owner, repo, filepath, ref)
	if res.StatusCode == 404 { // the workflow object exists, but the file is deleted
		logger.Warnf("file %s not found", filepath)
		return nil, nil
	}

	if err != nil {
		logger.Error(err, "error in fetching file content")
		return nil, err
	}

	decodedText, err := base64.StdEncoding.DecodeString(*file.Content)
	if err != nil {
		logger.Error(err, "error in decoding file content")
		return nil, err
	}
	return decodedText, nil
}

var _ adapter.ClientAdapter = (*ClientAdapterImpl)(nil) // Verify that *ClientAdapterImpl implements ClientAdapter.
