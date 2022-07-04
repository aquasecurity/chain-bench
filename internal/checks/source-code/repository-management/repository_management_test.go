package repositorymanagement

import (
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/aquasecurity/chain-bench/internal/checks/common"
	"github.com/aquasecurity/chain-bench/internal/checks/consts"
	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
	"github.com/aquasecurity/chain-bench/internal/testutils"
	"github.com/aquasecurity/chain-bench/internal/testutils/builders"
)

func TestRepositoryChecker(t *testing.T) {

	var checksMetadata checkmodels.CheckMetadataMap
	json.Unmarshal(metadataString, &checksMetadata)

	tests := []testutils.CheckTest{
		{
			Name: "Should fail for public repository without security.md file",
			Data: &checkmodels.CheckData{

				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithRepository(builders.NewRepositoryBuilder().WithPrivate(false).WithSecurityMdFile(false).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.2.1", checksMetadata.Checks["1.2.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Should return unknown if repository not fetched",
			Data: &checkmodels.CheckData{

				AssetsMetadata: builders.NewAssetsDataBuilder().WithNoRepositoryData().Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.2.1", checksMetadata.Checks["1.2.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_repository_is_missing}),
			},
		},
		{
			Name: "Should return unknown if organization not fetched",
			Data: &checkmodels.CheckData{

				AssetsMetadata: builders.NewAssetsDataBuilder().WithNoOrganization().Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.2.2", checksMetadata.Checks["1.2.2"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_organization_notFetched}),
				checkmodels.ToCheckRunResult("1.2.3", checksMetadata.Checks["1.2.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_organization_notFetched}),
				checkmodels.ToCheckRunResult("1.2.4", checksMetadata.Checks["1.2.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_organization_notFetched}),
			},
		},
		{
			Name: "Should fail for public repository without security.md file",
			Data: &checkmodels.CheckData{

				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithRepository(builders.NewRepositoryBuilder().WithPrivate(false).WithSecurityMdFile(false).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.2.1", checksMetadata.Checks["1.2.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Should fail for repository without creation limited to trusted users",
			Data: &checkmodels.CheckData{

				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().WithMembersCanCreateRepos(true).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.2.2", checksMetadata.Checks["1.2.2"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Should fail for repository without issue deletion limited to trusted users",
			Data: &checkmodels.CheckData{

				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().WithIssuesDeletionLimitation(false).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.2.4", checksMetadata.Checks["1.2.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Should fail for organization with no limitations for repository deletion",
			Data: &checkmodels.CheckData{

				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().WithReposDeletionLimitation(false).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.2.3", checksMetadata.Checks["1.2.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Valid input -all rules should pass",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().Build(),
			},
			Expected: []*checkmodels.CheckRunResult{},
		},
	}
	testutils.RunCheckTests(t, common.GetRegoRunAction(regoQuery, checksMetadata), tests, checksMetadata)
}
