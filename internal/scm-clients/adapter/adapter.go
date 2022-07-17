package adapter

import (
	"net/http"

	"github.com/aquasecurity/chain-bench/internal/models"
	pipelineModels "github.com/argonsecurity/pipeline-parser/pkg/models"
)

type ClientAdapter interface {
	Init(client *http.Client) error
	GetRepository(owner, repo, branchName string) (*models.Repository, string, error)
	ListRepositoryBranches(owner, repo string) ([]*models.Branch, error)
	GetCommit(organization string, repositoryName string, sha string) (*models.RepositoryCommit, error)
	GetBranchProtection(owner, repo, branch string) (*models.Protection, error)
	GetOrganization(owner string) (*models.Organization, error)
	GetRegistry(organization *models.Organization) (*models.PackageRegistry, error)
	ListOrganizationMembers(organization string) ([]*models.User, error)
	GetPipelines(owner, repo, branch string) ([]*pipelineModels.Pipeline, error)
	GetFileContent(owner, repo, path, ref string) ([]byte, error)
	GetAuthorizedUser() (*models.User, error)
}
