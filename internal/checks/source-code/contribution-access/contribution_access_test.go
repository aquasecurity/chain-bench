package contributionaccess

import (
	_ "embed"
	"testing"

	"github.com/aquasecurity/chain-bench/internal/checks/common"
	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
	"github.com/aquasecurity/chain-bench/internal/testutils"
	"github.com/aquasecurity/chain-bench/internal/testutils/builders"
)

func TestOrganizationChecker(t *testing.T) {
	tests := []testutils.CheckTest{
		{
			Name: "Should return unknown for organization without org settings permissions, without admin permissions, and with no commits",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().WithNoMembers().WithReposDefaultPermissions("").Build()).WithRepository(builders.NewRepositoryBuilder().WithNoCommits().Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.3.1", checksMetadata.Checks["1.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.3", checksMetadata.Checks["1.3.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.5", checksMetadata.Checks["1.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.7", checksMetadata.Checks["1.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.8", checksMetadata.Checks["1.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
			},
		},
		{
			Name: "Should fail for organization with unverified status",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().WithVerifiedBadge(false).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.3.9", checksMetadata.Checks["1.3.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Should fail for organization without strict default permission",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().
					WithReposDefaultPermissions("write").Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.3.8", checksMetadata.Checks["1.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Should fail for organization with 2mfa disabled",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().
					WithMFAEnabled(false).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.3.5", checksMetadata.Checks["1.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Should fail for organization with less then 2 admins",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().WithMembers("admin", 1).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.3.3", checksMetadata.Checks["1.3.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Should fail for repository with no 2 admins",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithRepository(builders.NewRepositoryBuilder().WithAdminCollborator(true, 1).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.3.7", checksMetadata.Checks["1.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Should fail for repository with inactive user",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().WithMembers("admin", 5).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.3.1", checksMetadata.Checks["1.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 inactive users"}),
			},
		},
		{
			Name: "valid input - all rules should pass",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().Build(),
			},
			Expected: []*checkmodels.CheckRunResult{},
		},
	}
	testutils.RunCheckTests(t, common.GetRegoRunAction(regoQuery, checksMetadata), tests, checksMetadata)
}
