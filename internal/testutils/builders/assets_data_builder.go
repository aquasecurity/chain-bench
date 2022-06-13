package builders

import (
	"github.com/argonsecurity/chain-bench/internal/models"
	"github.com/argonsecurity/chain-bench/internal/models/checkmodels"
	"github.com/argonsecurity/chain-bench/internal/testutils"
	"github.com/argonsecurity/chain-bench/internal/utils"
	pipelineParserModels "github.com/argonsecurity/pipeline-parser/pkg/models"
)

type AssetsDataBuilder struct {
	assetsData *checkmodels.AssetsData
}

func NewAssetsDataBuilder() *AssetsDataBuilder {
	return &AssetsDataBuilder{assetsData: &checkmodels.AssetsData{}}
}

func (b *AssetsDataBuilder) WithRepository(repo *models.Repository) *AssetsDataBuilder {
	b.assetsData.Repository = repo
	return b
}

func (b *AssetsDataBuilder) WithAuthorizedUser() *AssetsDataBuilder {
	b.assetsData.AuthorizedUser = &models.User{ID: utils.GetPtr(testutils.AuthorizedUserMockId)}
	return b
}

func (b *AssetsDataBuilder) WithOrganization(org *models.Organization) *AssetsDataBuilder {
	b.assetsData.Organization = org
	return b
}

func (b *AssetsDataBuilder) WithUsers(users []*models.User) *AssetsDataBuilder {
	b.assetsData.Users = users
	return b
}

func (b *AssetsDataBuilder) WithBranchProtections(bp *models.Protection) *AssetsDataBuilder {
	b.assetsData.BranchProtections = bp
	return b
}

func (b *AssetsDataBuilder) WithPackageRegistry(bp *models.PackageRegistry) *AssetsDataBuilder {
	b.assetsData.Registry = bp
	return b
}

func (b *AssetsDataBuilder) WithPipeline(pipeline *pipelineParserModels.Pipeline) *AssetsDataBuilder {
	if b.assetsData.Pipelines == nil {
		b.assetsData.Pipelines = []*pipelineParserModels.Pipeline{}
	}
	b.assetsData.Pipelines = append(b.assetsData.Pipelines, pipeline)
	return b
}

func (b *AssetsDataBuilder) WithZeroPipelines() *AssetsDataBuilder {
	b.assetsData.Pipelines = []*pipelineParserModels.Pipeline{}
	return b
}

func (b *AssetsDataBuilder) Build() *checkmodels.AssetsData {
	return b.assetsData
}

func (b *AssetsDataBuilder) WithBranch(branch *models.Branch) *AssetsDataBuilder {
	b.assetsData.Repository.Branches = append(b.assetsData.Repository.Branches, branch)
	return b
}
