package adapter

import (
	"net/http"

	"github.com/aquasecurity/chain-bench/internal/models"
	pipelineModels "github.com/argonsecurity/pipeline-parser/pkg/models"
)

type ClientAdapter interface {
	Init(client *http.Client, token string) error
	ListSupportedChecksIDs() ([]string, error)
	GetRepository(owner, repo, branchName string) (*models.Repository, error)
	ListRepositoryBranches(owner, repo string) ([]*models.Branch, error)
	GetBranchProtection(owner string, repo *models.Repository, branch string) (*models.Protection, error)
	GetOrganization(owner string) (*models.Organization, error)
	GetRegistry(organization *models.Organization) (*models.PackageRegistry, error)
	ListOrganizationMembers(organization string) ([]*models.User, error)
	GetPipelines(owner, repo, branch string) ([]*pipelineModels.Pipeline, error)
	GetAuthorizedUser() (*models.User, error)
}
