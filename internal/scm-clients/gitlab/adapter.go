package gitlab

import (
	"net/http"
	"strconv"

	"github.com/aquasecurity/chain-bench/internal/logger"
	"github.com/aquasecurity/chain-bench/internal/models"
	"github.com/aquasecurity/chain-bench/internal/scm-clients/adapter"
	pipelineModels "github.com/argonsecurity/pipeline-parser/pkg/models"
	"github.com/xanzy/go-gitlab"
)

var (
	Adapter ClientAdapterImpl
)

type ClientAdapterImpl struct {
	client GitlabClient
}

func (*ClientAdapterImpl) Init(client *http.Client, token string) error {
	glClient, err := InitClient(client, token)
	Adapter = ClientAdapterImpl{client: glClient}
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
func (ca *ClientAdapterImpl) GetRepository(owner string, repo string, branch string) (*models.Repository, error) {
	rep, _, err := ca.client.GetRepository(owner, repo)
	if err != nil {
		logger.Error(err, "error in fetching repository data")
		return nil, err
	}

	// TODO: ListCommits

	branches, err := ca.ListRepositoryBranches(owner, strconv.Itoa(rep.ID))
	if err != nil {
		logger.WarnE(err, "failed to fetch branches data")
	}

	// TODO: isRepoContainsSecurityMD

	// TODO: ListRepositoryCollaborators

	// TODO: ListRepositoryHooks

	return toRepository(rep, branches, nil, nil, nil, false), nil
}

// listRepositoryBranches implements clients.ClientAdapter
func (ca *ClientAdapterImpl) ListRepositoryBranches(owner string, repo string) ([]*models.Branch, error) {
	branches, _, err := ca.client.ListRepositoryBranches(owner, repo)
	if err != nil {
		logger.Error(err, "error in fetching branches")
		return nil, err
	}
	enhancedBranches := []*gitlab.Branch{}

	for _, b := range branches {
		//TODO: GetCommit
		if err != nil {
			logger.WarnE(err, "failed to fetch branches commit")
		} else {
			branch := &gitlab.Branch{
				Name:      b.Name,
				Commit:    b.Commit,
				Protected: b.Protected,
			}
			enhancedBranches = append(enhancedBranches, branch)
		}
	}
	return toBranches(enhancedBranches), nil
}

func (ca *ClientAdapterImpl) GetOrganization(owner string) (*models.Organization, error) {
	org, _, err := ca.client.GetOrganization(owner)
	if err != nil {
		logger.Error(err, "error in fetching organization")
		return nil, err
	}

	return toOrganization(org, nil), nil
}

// GetBranchProtection implements clients.ClientAdapter
func (ca *ClientAdapterImpl) GetBranchProtection(owner string, repo *models.Repository, branch string) (*models.Protection, error) {
	projectId := strconv.Itoa(int(*repo.ID))
	prot, _, err := ca.client.GetBranchProtection(owner, projectId, branch)
	if err != nil {
		logger.Error(err, "error in fetching branch protection")
		return nil, err
	}

	appConf, _, err := ca.client.GetApprovalConfiguration(projectId)
	if err != nil {
		logger.WarnE(err, "failed to fetch approval configuration")
	}

	pushRules, _, err := ca.client.GetProjectPushRules(projectId)
	if err != nil {
		logger.WarnE(err, "failed to fetch approval configuration")
	}

	appRules, _, err := ca.client.GetProjectApprovalRules(projectId)
	if err != nil {
		logger.WarnE(err, "failed to fetch approval rules")
	}

	proj, _, err := ca.client.GetRepository(owner, *repo.Name)
	if err != nil {
		logger.WarnE(err, "failed to fetch project")
	}
	return toBranchProtection(proj, prot, appConf, appRules, pushRules), nil
}

func (ca *ClientAdapterImpl) ListOrganizationMembers(organization string) ([]*models.User, error) {
	// TODO
	return nil, nil
}

func (ca *ClientAdapterImpl) GetRegistry(organization *models.Organization) (*models.PackageRegistry, error) {
	//TODO
	return nil, nil
}

func (ca *ClientAdapterImpl) GetPipelines(owner string, repo string, branch string) ([]*pipelineModels.Pipeline, error) {
	//TODO
	return nil, nil
}

var _ adapter.ClientAdapter = (*ClientAdapterImpl)(nil) // Verify that *ClientAdapterImpl implements ClientAdapter.
