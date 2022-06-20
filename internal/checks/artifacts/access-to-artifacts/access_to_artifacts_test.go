package accesstoartifacts

import (
	"testing"

	"github.com/aquasecurity/chain-bench/internal/checks/common"
	"github.com/aquasecurity/chain-bench/internal/checks/consts"
	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
	"github.com/aquasecurity/chain-bench/internal/testutils"
	"github.com/aquasecurity/chain-bench/internal/testutils/builders"
)

const (
	vulnerabilityScanningTask = "argonsecurity/scanner-action"
)

func TestAccessToArtifactsChecker(t *testing.T) {
	tests := []testutils.CheckTest{
		{
			Name: "no org settings permissions",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().WithReposDefaultPermissions("").Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("4.2.3", checksMetadata.Checks["4.2.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_organization_missingMinimalPermissions}),
			},
		},
		{
			Name: "no org packages permissions",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithPackageRegistry(builders.NewRegistryBuilder().WithNoPackages().Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("4.2.5", checksMetadata.Checks["4.2.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_organization_hooks_missingMinimalPermissions}),
			},
		},
		{
			Name: "Package registry with 2mfa disabled",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithPackageRegistry(builders.NewRegistryBuilder().WithTwoFactorAuthenticationEnabled(false).Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("4.2.3", checksMetadata.Checks["4.2.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Package registry with 1 public package under private repo",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithPackageRegistry(builders.NewRegistryBuilder().WithPackages("npm", "public", true).Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("4.2.5", checksMetadata.Checks["4.2.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 anonymous accessed packages"}),
			},
		},
		{
			Name: "Valid input",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().Build(),
			},
			Expected: []*checkmodels.CheckRunResult{},
		},
	}
	testutils.RunCheckTests(t, common.GetRegoRunAction(regoQuery, checksMetadata), tests, checksMetadata)
}
