package packageregistries

import (
	"testing"

	"github.com/aquasecurity/chain-bench/internal/checks/common"
	"github.com/aquasecurity/chain-bench/internal/checks/consts"
	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
	"github.com/aquasecurity/chain-bench/internal/testutils"
	"github.com/aquasecurity/chain-bench/internal/testutils/builders"
	"github.com/aquasecurity/chain-bench/internal/utils"
)

func TestPackageRegistryChecker(t *testing.T) {
	tests := []testutils.CheckTest{

		{
			Name: "should return unknown when there are no hooks permissions",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().WithNoPackageWebHooks().Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("4.3.4", checksMetadata.Checks["4.3.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_hooks_missingMinimalPermissions}),
			},
		},
		{
			Name: "should fail and return the number of unsecured hooks when the user has 1 org webhook with no ssl",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().WithPackageWebHooks("https://endpoint.com", "1", utils.GetPtr("**")).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("4.3.4", checksMetadata.Checks["4.3.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 unsecured webhooks"}),
			},
		},
		{
			Name: "should fail and return the number of unsecured hooks when the user has 1 repo webhook with no secret",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithRepository(builders.NewRepositoryBuilder().WithPackageWebHooks("https://endpoint.com", "0", nil).Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("4.3.4", checksMetadata.Checks["4.3.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 unsecured webhooks"}),
			},
		},
		{
			Name: "should fail and return the number of unsecured hooks when the user has 1 org webhook with no https",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().WithPackageWebHooks("http://endpoint.com", "0", utils.GetPtr("**")).
						Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("4.3.4", checksMetadata.Checks["4.3.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 unsecured webhooks"}),
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
