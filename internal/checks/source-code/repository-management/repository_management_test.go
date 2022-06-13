package repositorymanagement

import (
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/aquasecurity/chain-bench/internal/checks/common"
	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
	"github.com/aquasecurity/chain-bench/internal/testutils"
	"github.com/aquasecurity/chain-bench/internal/testutils/builders"
)

func TestRepositoryChecker(t *testing.T) {

	var checksMetadata checkmodels.CheckMetadataMap
	json.Unmarshal(metadataString, &checksMetadata)

	tests := []testutils.CheckTest{
		{
			Name: "Public repository without security.md file",
			Data: &checkmodels.CheckData{

				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().WithReposDeletionLimitation(true).WithMembersCanCreateRepos(true).WithIssuesDeletionLimitation(true).Build()).
					WithRepository(builders.NewRepositoryBuilder().WithPrivate(false).WithSecurityMdFile(false).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.2.1", checksMetadata.Checks["1.2.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.2.2", checksMetadata.Checks["1.2.2"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.2.3", checksMetadata.Checks["1.2.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.2.4", checksMetadata.Checks["1.2.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
			},
		},
		{
			Name: "Private repository without security.md file",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().WithReposDeletionLimitation(true).WithMembersCanCreateRepos(true).WithIssuesDeletionLimitation(true).Build()).
					WithRepository(builders.NewRepositoryBuilder().WithPrivate(true).WithSecurityMdFile(false).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.2.1", checksMetadata.Checks["1.2.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.2.2", checksMetadata.Checks["1.2.2"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.2.3", checksMetadata.Checks["1.2.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.2.4", checksMetadata.Checks["1.2.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
			},
		},
		{
			Name: "Public repository with security.md file",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().WithReposDeletionLimitation(true).WithMembersCanCreateRepos(true).WithIssuesDeletionLimitation(true).Build()).
					WithRepository(builders.NewRepositoryBuilder().WithPrivate(false).WithSecurityMdFile(true).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.2.1", checksMetadata.Checks["1.2.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.2.2", checksMetadata.Checks["1.2.2"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.2.3", checksMetadata.Checks["1.2.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.2.4", checksMetadata.Checks["1.2.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
			},
		},
		{
			Name: "Private repository with security.md file",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().WithReposDeletionLimitation(true).WithMembersCanCreateRepos(true).WithIssuesDeletionLimitation(true).Build()).
					WithRepository(builders.NewRepositoryBuilder().WithPrivate(true).WithSecurityMdFile(true).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.2.1", checksMetadata.Checks["1.2.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.2.2", checksMetadata.Checks["1.2.2"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.2.3", checksMetadata.Checks["1.2.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.2.4", checksMetadata.Checks["1.2.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
			},
		},
		{
			Name: "Repository without stale branches",
			Data: &checkmodels.CheckData{

				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().WithReposDeletionLimitation(true).WithIssuesDeletionLimitation(true).WithMembersCanCreateRepos(true).Build()).
					WithRepository(builders.NewRepositoryBuilder().WithPrivate(true).WithSecurityMdFile(false).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.2.1", checksMetadata.Checks["1.2.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.2.2", checksMetadata.Checks["1.2.2"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.2.3", checksMetadata.Checks["1.2.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.2.4", checksMetadata.Checks["1.2.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
			},
		},
		{
			Name: "Organization with repository and issue deletion limited to trusted users and with 1 stale branch",
			Data: &checkmodels.CheckData{

				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().WithReposDeletionLimitation(true).WithIssuesDeletionLimitation(true).WithMembersCanCreateRepos(true).Build()).
					WithRepository(builders.NewRepositoryBuilder().WithPrivate(true).WithSecurityMdFile(true).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.2.1", checksMetadata.Checks["1.2.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.2.2", checksMetadata.Checks["1.2.2"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.2.3", checksMetadata.Checks["1.2.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.2.4", checksMetadata.Checks["1.2.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
			},
		},
		{
			Name: "Organization with no limitations for repository deletion",
			Data: &checkmodels.CheckData{

				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().WithReposDeletionLimitation(false).WithMembersCanCreateRepos(true).WithIssuesDeletionLimitation(true).Build()).
					WithRepository(builders.NewRepositoryBuilder().WithPrivate(true).WithSecurityMdFile(true).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.2.1", checksMetadata.Checks["1.2.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.2.2", checksMetadata.Checks["1.2.2"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.2.3", checksMetadata.Checks["1.2.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.2.4", checksMetadata.Checks["1.2.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
			},
		},
		{
			Name: "Organization with no limitations for issue deletion",
			Data: &checkmodels.CheckData{

				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().WithReposDeletionLimitation(true).WithMembersCanCreateRepos(true).WithIssuesDeletionLimitation(false).Build()).
					WithRepository(builders.NewRepositoryBuilder().WithPrivate(true).WithSecurityMdFile(true).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.2.1", checksMetadata.Checks["1.2.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.2.2", checksMetadata.Checks["1.2.2"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.2.3", checksMetadata.Checks["1.2.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.2.4", checksMetadata.Checks["1.2.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Organization with limitations for repositories creation",
			Data: &checkmodels.CheckData{

				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().WithReposDeletionLimitation(true).WithMembersCanCreateRepos(false).WithIssuesDeletionLimitation(false).Build()).
					WithRepository(builders.NewRepositoryBuilder().WithPrivate(true).WithSecurityMdFile(true).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.2.1", checksMetadata.Checks["1.2.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.2.2", checksMetadata.Checks["1.2.2"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.2.3", checksMetadata.Checks["1.2.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.2.4", checksMetadata.Checks["1.2.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
	}
	testutils.RunCheckTests(t, common.GetRegoRunAction(regoQuery, checksMetadata), tests)
}
